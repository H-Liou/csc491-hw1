#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-Lite signature table ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_ENTRIES 2048 // 2K entries: 6 bits each = 1.5 KiB
struct SHIP_ENTRY {
    uint8_t reuse; // 6-bit saturating counter
};
std::vector<SHIP_ENTRY> ship_table;

// --- DRRIP set-dueling ---
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1)); // 10-bit selector
#define DUEL_SET_INTERVAL 64
#define SRRIP_LEADER_SETS 32
#define BRRIP_LEADER_SETS 32
std::vector<uint8_t> set_type; // 0: follower, 1: SRRIP leader, 2: BRRIP leader

// --- Per-block RRPV ---
struct BLOCK_META {
    uint8_t rrpv; // 2 bits
    uint16_t signature; // 11 bits (PC hash)
};
std::vector<BLOCK_META> block_meta;

// --- Streaming detector ---
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3
struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};
std::vector<STREAM_DETECTOR> stream_detector;

// --- Stats ---
uint64_t access_counter = 0;
uint64_t streaming_bypass = 0;
uint64_t ship_hits = 0;
uint64_t ship_promotes = 0;
uint64_t srrip_inserts = 0;
uint64_t brrip_inserts = 0;
uint64_t decay_events = 0;

// --- Helper: get block meta index ---
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// --- SHiP signature hash ---
inline uint16_t get_signature(uint64_t PC) {
    // Use a simple hash: lower 11 bits of PC
    return (PC ^ (PC >> 2)) & 0x7FF;
}

// --- Streaming detection: updates per access ---
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

// --- Initialization ---
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    ship_table.resize(SHIP_TABLE_ENTRIES);
    stream_detector.resize(LLC_SETS);
    set_type.resize(LLC_SETS);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3; // RRIP max (LRU)
        block_meta[i].signature = 0;
    }
    for (size_t i = 0; i < ship_table.size(); i++) {
        ship_table[i].reuse = SHIP_SIG_BITS / 2; // neutral
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
    // Set-dueling: assign leader sets
    for (size_t i = 0; i < set_type.size(); i++) {
        if (i % DUEL_SET_INTERVAL < SRRIP_LEADER_SETS)
            set_type[i] = 1; // SRRIP leader
        else if (i % DUEL_SET_INTERVAL >= DUEL_SET_INTERVAL - BRRIP_LEADER_SETS)
            set_type[i] = 2; // BRRIP leader
        else
            set_type[i] = 0; // follower
    }
    access_counter = 0;
    streaming_bypass = 0;
    ship_hits = 0;
    ship_promotes = 0;
    srrip_inserts = 0;
    brrip_inserts = 0;
    decay_events = 0;
}

// --- Victim selection: RRIP ---
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

// --- Update replacement state ---
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

    // Periodic SHiP decay: every 4096 accesses, halve all counters
    if ((access_counter & 0xFFF) == 0) {
        for (size_t i = 0; i < ship_table.size(); i++) {
            ship_table[i].reuse >>= 1;
        }
        decay_events++;
    }

    // --- Streaming bypass ---
    if (!hit && stream_detector[set].streaming) {
        meta.rrpv = 3; // mark as LRU (effectively bypass)
        streaming_bypass++;
        return;
    }

    // --- SHiP signature ---
    uint16_t sig = get_signature(PC);

    // --- On cache hit ---
    if (hit) {
        // Promote block to MRU
        meta.rrpv = 0;
        // SHiP: increment reuse counter (max saturate)
        if (ship_table[sig].reuse < ((1 << SHIP_SIG_BITS) - 1))
            ship_table[sig].reuse++;
        ship_hits++;
        ship_promotes++;
        return;
    }

    // --- On miss: insertion ---
    meta.signature = sig;
    uint8_t ship_val = ship_table[sig].reuse;

    // --- DRRIP set-dueling ---
    uint8_t ins_rrpv = 2; // default SRRIP insertion
    if (set_type[set] == 1) {
        // SRRIP leader: always insert at RRPV=2
        ins_rrpv = 2;
        srrip_inserts++;
    } else if (set_type[set] == 2) {
        // BRRIP leader: insert at RRPV=2 with 1/32 probability, else RRPV=3
        if ((access_counter & 0x1F) == 0) {
            ins_rrpv = 2;
        } else {
            ins_rrpv = 3;
        }
        brrip_inserts++;
    } else {
        // Follower: use PSEL to choose SRRIP or BRRIP
        if (psel >= (1 << (PSEL_BITS - 1))) {
            ins_rrpv = 2; // SRRIP
            srrip_inserts++;
        } else {
            if ((access_counter & 0x1F) == 0)
                ins_rrpv = 2;
            else
                ins_rrpv = 3;
            brrip_inserts++;
        }
    }

    // --- SHiP bias ---
    // If signature shows strong reuse, insert at MRU
    if (ship_val >= ((1 << SHIP_SIG_BITS) - 2)) {
        meta.rrpv = 0;
        ship_promotes++;
    } else if (ship_val <= 1) {
        meta.rrpv = 3;
    } else {
        meta.rrpv = ins_rrpv;
    }

    // --- Update PSEL ---
    if (set_type[set] == 1) {
        // SRRIP leader: if hit, increment PSEL
        if (hit && psel < ((1 << PSEL_BITS) - 1))
            psel++;
    } else if (set_type[set] == 2) {
        // BRRIP leader: if hit, decrement PSEL
        if (hit && psel > 0)
            psel--;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "SHiP-Lite DRRIP + Streaming Bypass\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming bypasses: " << streaming_bypass << "\n";
    std::cout << "SHiP hits: " << ship_hits << "\n";
    std::cout << "SHiP MRU promotions: " << ship_promotes << "\n";
    std::cout << "SRRIP inserts: " << srrip_inserts << "\n";
    std::cout << "BRRIP inserts: " << brrip_inserts << "\n";
    std::cout << "SHiP decay events: " << decay_events << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    std::cout << "SHiP-Lite DRRIP heartbeat: accesses=" << access_counter
              << ", streaming_bypass=" << streaming_bypass
              << ", ship_hits=" << ship_hits
              << ", ship_promotes=" << ship_promotes
              << ", srrip_inserts=" << srrip_inserts
              << ", brrip_inserts=" << brrip_inserts
              << ", decay_events=" << decay_events << "\n";
}