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
#define RRPV_INSERT_SRRIP 2   // SRRIP: insert at RRPV=2
#define RRPV_INSERT_BIP 3     // BIP: insert at RRPV=3 (MRU only every 1/32 fills)
#define RRPV_INSERT_MRU 0

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX ((1 << DEAD_BITS) - 1)
#define DEAD_DECAY_PERIOD 4096
#define DEAD_THRESHOLD 1

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3 // 3/4 monotonic deltas triggers streaming

// DRRIP/DIP
#define LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)
#define SRRIP_LEADER_SET_MASK 0x3F
#define BIP_LEADER_SET_MASK 0x3F

struct BLOCK_META {
    uint8_t rrpv;         // 2 bits
    uint8_t dead;         // 2 bits
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<BLOCK_META> block_meta;
std::vector<STREAM_DETECTOR> stream_detector;

// DRRIP global policy selector
uint16_t psel = PSEL_INIT;

// Leader sets: first 32 for SRRIP, next 32 for BIP
std::vector<uint8_t> is_srrip_leader;
std::vector<uint8_t> is_bip_leader;

uint64_t access_counter = 0;
uint64_t streaming_bypass = 0;
uint64_t dead_decay_count = 0;

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

// Dead-block decay: periodically decay all dead counters
void decay_dead_counters() {
    for (size_t i = 0; i < block_meta.size(); i++) {
        if (block_meta[i].dead > 0)
            block_meta[i].dead--;
    }
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    stream_detector.resize(LLC_SETS);
    is_srrip_leader.resize(LLC_SETS, 0);
    is_bip_leader.resize(LLC_SETS, 0);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = RRPV_MAX;
        block_meta[i].dead = DEAD_MAX / 2;
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
    // Assign leader sets (first 32 for SRRIP, next 32 for BIP)
    for (uint32_t i = 0; i < LEADER_SETS; i++) {
        is_srrip_leader[i] = 1;
        is_bip_leader[LLC_SETS - 1 - i] = 1;
    }
    access_counter = 0;
    streaming_bypass = 0;
    dead_decay_count = 0;
    psel = PSEL_INIT;
}

// Victim selection: SRRIP, prefer dead blocks
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV_MAX and dead counter == 0
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX && block_meta[idx].dead == 0)
            return way;
    }
    // Next, any block with RRPV_MAX
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
    // Second pass: dead blocks
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX && block_meta[idx].dead <= DEAD_THRESHOLD)
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

    // Periodically decay dead counters (every DEAD_DECAY_PERIOD accesses)
    if ((access_counter & (DEAD_DECAY_PERIOD - 1)) == 0) {
        decay_dead_counters();
        dead_decay_count++;
    }

    // On streaming: bypass fill (do not insert into cache)
    if (stream_detector[set].streaming) {
        meta.rrpv = RRPV_MAX; // mark as least likely reused
        meta.dead = DEAD_MAX;
        streaming_bypass++;
        return;
    }

    // On cache hit
    if (hit) {
        // Promote block to MRU
        meta.rrpv = RRPV_INSERT_MRU;
        // Mark block as not dead
        if (meta.dead > 0) meta.dead--;
        return;
    }

    // DRRIP: decide insertion depth
    uint8_t use_srrip = 0, use_bip = 0;
    if (is_srrip_leader[set]) use_srrip = 1;
    if (is_bip_leader[set]) use_bip = 1;

    uint8_t insertion_rrpv = RRPV_INSERT_SRRIP;
    // BIP: insert at RRPV_MAX except every 1/32 fills (MRU)
    static uint32_t bip_ctr = 0;
    if (use_bip || (!use_srrip && !use_bip && psel < (PSEL_MAX / 2))) {
        bip_ctr++;
        if ((bip_ctr & 0x1F) == 0)
            insertion_rrpv = RRPV_INSERT_MRU;
        else
            insertion_rrpv = RRPV_INSERT_BIP;
    } else if (use_srrip || (!use_srrip && !use_bip && psel >= (PSEL_MAX / 2))) {
        insertion_rrpv = RRPV_INSERT_SRRIP;
    }

    // Insert block with chosen RRPV
    meta.rrpv = insertion_rrpv;
    meta.dead = DEAD_MAX;

    // Dead-block: if dead counter is low, give moderate chance
    if (meta.dead <= DEAD_THRESHOLD)
        meta.rrpv = RRPV_INSERT_SRRIP;

    // Update PSEL for leader sets
    if (use_srrip) {
        if (hit && psel < PSEL_MAX) psel++;
    }
    if (use_bip) {
        if (hit && psel > 0) psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DBS-DRRIP: DRRIP-BIP Hybrid Streaming Bypass Dead-Block Decay stats\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming bypasses: " << streaming_bypass << "\n";
    std::cout << "Dead-block decay rounds: " << dead_decay_count << "\n";
    std::cout << "PSEL value: " << psel << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DBS-DRRIP heartbeat: accesses=" << access_counter
              << ", streaming_bypass=" << streaming_bypass
              << ", dead_decay=" << dead_decay_count
              << ", psel=" << psel << "\n";
}