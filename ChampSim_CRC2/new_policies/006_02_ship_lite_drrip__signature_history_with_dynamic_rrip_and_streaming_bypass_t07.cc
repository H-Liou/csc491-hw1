#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: Signature table
#define SHIP_SIG_BITS 12         // 4K signatures
#define SHIP_SIG_MASK ((1<<SHIP_SIG_BITS)-1)
#define SHIP_OUTCOME_BITS 2      // 2 bits per signature

struct SHIP_ENTRY {
    uint8_t outcome; // 2 bits: saturating counter (reuse, non-reuse)
};

std::vector<SHIP_ENTRY> ship_table; // 4096 entries

// Per-block metadata: 2 bits RRPV + 12 bits PC signature
struct BLOCK_META {
    uint8_t rrpv;       // 2 bits
    uint16_t signature; // 12 bits
};
std::vector<BLOCK_META> block_meta;

// DRRIP: Set-dueling, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
struct DRRIP_DUEL {
    uint16_t psel; // 10 bits
    std::vector<bool> is_srrip_leader; // NUM_LEADER_SETS
    std::vector<bool> is_brrip_leader; // NUM_LEADER_SETS
};
DRRIP_DUEL drrip_duel;

// Streaming detector: per set
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3
struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};
std::vector<STREAM_DETECTOR> stream_detector;

// Stats
uint64_t access_counter = 0;
uint64_t streaming_bypass = 0;
uint64_t ship_hits = 0;
uint64_t drrip_srrip_inserts = 0;
uint64_t drrip_brrip_inserts = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: get SHiP signature (hash lower 12 bits of PC)
inline uint16_t get_signature(uint64_t PC) {
    return uint16_t((PC >> 2) & SHIP_SIG_MASK);
}

// Streaming detection: updates per access
void update_streaming_detector(uint32_t set, uint64_t curr_addr) {
    STREAM_DETECTOR &sd = stream_detector[set];
    int64_t delta = curr_addr - sd.last_addr;
    if (sd.last_addr != 0) {
        sd.delta_history[sd.ptr] = delta;
        sd.ptr = (sd.ptr + 1) % STREAM_DELTA_HISTORY;
    }
    sd.last_addr = curr_addr;
    // Check monotonicity
    int positive = 0, negative = 0, nonzero = 0;
    for (int i = 0; i < STREAM_DELTA_HISTORY; i++) {
        if (sd.delta_history[i] > 0) positive++;
        else if (sd.delta_history[i] < 0) negative++;
        if (sd.delta_history[i] != 0) nonzero++;
    }
    if (nonzero >= STREAM_DELTA_THRESHOLD &&
        (positive >= STREAM_DELTA_THRESHOLD || negative >= STREAM_DELTA_THRESHOLD)) {
        sd.streaming = true;
    } else {
        sd.streaming = false;
    }
}

// DRRIP: get insertion RRPV for current set
uint8_t get_drrip_insertion(uint32_t set) {
    // Leader sets: first NUM_LEADER_SETS sets for SRRIP, next NUM_LEADER_SETS for BRRIP
    if (drrip_duel.is_srrip_leader[set])
        return 2; // SRRIP: insert at RRPV=2
    else if (drrip_duel.is_brrip_leader[set])
        return (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert mostly at RRPV=3
    else
        return (drrip_duel.psel >= (1 << (PSEL_BITS-1))) ?
            ((rand() % 32 == 0) ? 2 : 3) : 2; // PSEL selects BRRIP or SRRIP
}

// DRRIP: update PSEL based on hits/misses in leader sets
void update_drrip_psel(uint32_t set, uint8_t hit) {
    if (drrip_duel.is_srrip_leader[set]) {
        if (hit && drrip_duel.psel < ((1<<PSEL_BITS)-1)) drrip_duel.psel++;
    }
    if (drrip_duel.is_brrip_leader[set]) {
        if (hit && drrip_duel.psel > 0) drrip_duel.psel--;
    }
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    ship_table.resize(1<<SHIP_SIG_BITS);
    stream_detector.resize(LLC_SETS);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3; // LRU
        block_meta[i].signature = 0;
    }
    for (size_t i = 0; i < ship_table.size(); i++) {
        ship_table[i].outcome = 1; // neutral
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }

    // DRRIP set-dueling
    drrip_duel.psel = 1 << (PSEL_BITS-1); // midpoint
    drrip_duel.is_srrip_leader.resize(LLC_SETS, false);
    drrip_duel.is_brrip_leader.resize(LLC_SETS, false);
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        drrip_duel.is_srrip_leader[i] = true;
        drrip_duel.is_brrip_leader[i+NUM_LEADER_SETS] = true;
    }

    access_counter = 0;
    streaming_bypass = 0;
    ship_hits = 0;
    drrip_srrip_inserts = 0;
    drrip_brrip_inserts = 0;
}

// Victim selection: RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV=3 (LRU)
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv < 3)
            block_meta[idx].rrpv++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
            return way;
    }
    // If still none, pick way 0
    return 0;
}

// Update replacement state
void UpdateReplacementState(
    uint32_t cpu,
    uint32_t set,
    uint32_t way,
    uint64_t paddr,
    uint64_t PC,
    uint64_t victim_addr,
    uint32_t type,
    uint8_t hit
) {
    access_counter++;
    size_t idx = get_block_meta_idx(set, way);
    BLOCK_META &meta = block_meta[idx];

    // Streaming detection (per set)
    update_streaming_detector(set, paddr);

    // DRRIP set-dueling update
    update_drrip_psel(set, hit);

    uint16_t sig = get_signature(PC);
    SHIP_ENTRY &ship = ship_table[sig];

    // On streaming: insert with high RRPV (bypass effect)
    if (!hit && stream_detector[set].streaming) {
        meta.rrpv = 3;
        meta.signature = sig;
        streaming_bypass++;
        return;
    }

    // On cache hit
    if (hit) {
        // Promote block to MRU
        meta.rrpv = 0;
        ship_hits++;
        // If signature matches, increment SHiP outcome (max saturate)
        if (meta.signature == sig && ship.outcome < 3)
            ship.outcome++;
        return;
    }

    // On miss: insertion
    meta.signature = sig;

    // Choose insertion RRPV
    uint8_t insert_rrpv = 2; // default

    // SHiP outcome: if outcome counter high, insert at MRU (rrpv=0)
    if (ship.outcome >= 2) {
        insert_rrpv = 0;
    } else {
        // Use DRRIP set-dueling
        insert_rrpv = get_drrip_insertion(set);
        if (insert_rrpv == 2) drrip_srrip_inserts++;
        else drrip_brrip_inserts++;
    }
    meta.rrpv = insert_rrpv;

    // On fill: reset SHiP outcome if block is victim (i.e., not reused)
    if (!hit && meta.signature != 0 && ship.outcome > 0)
        ship.outcome--;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite DRRIP: Signature History + Dynamic RRIP + Streaming Bypass\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming bypasses: " << streaming_bypass << "\n";
    std::cout << "SHiP hits/promotes: " << ship_hits << "\n";
    std::cout << "DRRIP SRRIP inserts: " << drrip_srrip_inserts << "\n";
    std::cout << "DRRIP BRRIP inserts: " << drrip_brrip_inserts << "\n";
    std::cout << "PSEL: " << drrip_duel.psel << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP-Lite DRRIP heartbeat: accesses=" << access_counter
              << ", streaming_bypass=" << streaming_bypass
              << ", ship_hits=" << ship_hits
              << ", srrip_inserts=" << drrip_srrip_inserts
              << ", brrip_inserts=" << drrip_brrip_inserts
              << ", PSEL=" << drrip_duel.psel << "\n";
}