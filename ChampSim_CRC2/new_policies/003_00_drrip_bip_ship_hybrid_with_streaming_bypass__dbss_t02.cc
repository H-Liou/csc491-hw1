#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define RRPV_INSERT_DISTANT RRPV_MAX
#define RRPV_INSERT_MRU 0

// DRRIP constants
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define SRRIP_LEADER_SETS 32
#define BRRIP_LEADER_SETS 32

// SHiP-lite constants
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1 << SHIP_COUNTER_BITS) - 1)
#define SHIP_REUSE_HIGH (SHIP_COUNTER_MAX - 1)

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3 // 3/4 monotonic deltas triggers streaming

struct BLOCK_META {
    uint8_t rrpv;         // 2 bits
    uint8_t ship_sig;     // 6 bits
};

struct SHIP_SIG_ENTRY {
    uint8_t reuse_counter; // 2 bits
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<BLOCK_META> block_meta;
std::vector<SHIP_SIG_ENTRY> ship_sig_table;
std::vector<STREAM_DETECTOR> stream_detector;

// DRRIP set-dueling
std::vector<uint8_t> is_srrip_leader; // 1 if SRRIP leader, 0 if BRRIP leader, else follower
uint32_t psel = PSEL_MAX / 2;

uint64_t access_counter = 0;
uint64_t streaming_bypass = 0;
uint64_t ship_promote = 0;

// Helper: get SHiP signature from PC
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 2) ^ (PC >> 7)) & (SHIP_SIG_ENTRIES - 1);
}

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
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

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    ship_sig_table.resize(SHIP_SIG_ENTRIES);
    stream_detector.resize(LLC_SETS);
    is_srrip_leader.resize(LLC_SETS, 0);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = RRPV_MAX;
        block_meta[i].ship_sig = 0;
    }
    for (size_t i = 0; i < ship_sig_table.size(); i++) {
        ship_sig_table[i].reuse_counter = 0;
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
    // Assign leader sets for DRRIP set-dueling
    for (uint32_t i = 0; i < SRRIP_LEADER_SETS; i++)
        is_srrip_leader[i] = 1;
    for (uint32_t i = LLC_SETS - BRRIP_LEADER_SETS; i < LLC_SETS; i++)
        is_srrip_leader[i] = 2; // 2 means BRRIP leader
    psel = PSEL_MAX / 2;
    access_counter = 0;
    streaming_bypass = 0;
    ship_promote = 0;
}

// Victim selection: SRRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV_MAX
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv < RRPV_MAX)
            block_meta[idx].rrpv++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX)
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

    // SHiP signature
    uint8_t sig = get_ship_sig(PC);

    // On cache hit
    if (hit) {
        // Update SHiP reuse counter
        if (ship_sig_table[sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[sig].reuse_counter++;
        // Promote block to MRU
        meta.rrpv = RRPV_INSERT_MRU;
        return;
    }

    // On cache fill (miss)
    meta.ship_sig = sig;

    // Streaming phase: bypass fill (do not insert into cache)
    if (stream_detector[set].streaming) {
        streaming_bypass++;
        // Do not update RRPV; block will be overwritten
        meta.rrpv = RRPV_MAX;
        return;
    }

    // SHiP predicts high reuse: insert at MRU
    if (ship_sig_table[sig].reuse_counter >= SHIP_REUSE_HIGH) {
        meta.rrpv = RRPV_INSERT_MRU;
        ship_promote++;
        return;
    }

    // DRRIP set-dueling: choose insertion depth
    uint8_t leader_type = is_srrip_leader[set];
    bool use_srrip = false;
    if (leader_type == 1) use_srrip = true; // SRRIP leader
    else if (leader_type == 2) use_srrip = false; // BRRIP leader
    else use_srrip = (psel >= (PSEL_MAX / 2)); // Follower sets

    if (use_srrip) {
        meta.rrpv = RRPV_INSERT_DISTANT; // SRRIP: always distant
    } else {
        // BRRIP: distant with low probability (1/32), else MRU
        if ((access_counter & 31) == 0)
            meta.rrpv = RRPV_INSERT_DISTANT;
        else
            meta.rrpv = RRPV_INSERT_MRU;
    }

    // On victim eviction: update SHiP reuse counter
    uint32_t victim_way = GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
    size_t victim_idx = get_block_meta_idx(set, victim_way);
    uint8_t victim_sig = block_meta[victim_idx].ship_sig;
    // If block was hit before eviction, increment reuse; else, decrement
    if (block_meta[victim_idx].rrpv == RRPV_INSERT_MRU) {
        if (ship_sig_table[victim_sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[victim_sig].reuse_counter++;
    } else {
        if (ship_sig_table[victim_sig].reuse_counter > 0)
            ship_sig_table[victim_sig].reuse_counter--;
    }

    // DRRIP set-dueling: update PSEL
    if (leader_type == 1) { // SRRIP leader
        if (hit && psel < PSEL_MAX) psel++;
    } else if (leader_type == 2) { // BRRIP leader
        if (hit && psel > 0) psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DBSS: DRRIP-BIP-SHiP Hybrid with Streaming Bypass stats\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming bypasses: " << streaming_bypass << "\n";
    std::cout << "SHiP MRU promotions: " << ship_promote << "\n";
    std::cout << "PSEL value: " << psel << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DBSS heartbeat: accesses=" << access_counter
              << ", streaming_bypass=" << streaming_bypass
              << ", ship_promote=" << ship_promote
              << ", PSEL=" << psel << "\n";
}