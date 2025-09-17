#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Dead-block predictor: 2 bits/block (reuse counter)
uint8_t reuse_counter[LLC_SETS][LLC_WAYS];

// Streaming detector: 3 bits/set
struct StreamSet {
    uint64_t last_addr;
    uint8_t stride_count; // up to 3
    uint8_t streaming;    // 1 if streaming detected
    uint8_t window;       // streaming window countdown
};
StreamSet stream_sets[LLC_SETS];

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// Dead-block threshold: if reuse_counter == 0, treat as dead
const uint8_t DEAD_THRESHOLD = 0;

// Decay interval (in accesses)
const uint32_t DECAY_INTERVAL = 4096;
uint32_t access_counter = 0;

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(reuse_counter, 1, sizeof(reuse_counter)); // weakly reused
    memset(stream_sets, 0, sizeof(stream_sets));
    access_counter = 0;
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Dead-block: prefer blocks with RRPV==RRIP_MAX
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    // If none, increment RRPV and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] < RRIP_MAX)
            rrpv[set][way]++;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
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

    // --- Streaming detector ---
    StreamSet &ss = stream_sets[set];
    uint64_t cur_addr = paddr >> 6; // cache line granularity
    int64_t stride = cur_addr - ss.last_addr;
    if (ss.last_addr != 0 && (stride == 1 || stride == -1)) {
        if (ss.stride_count < 3) ss.stride_count++;
        if (ss.stride_count == 3 && !ss.streaming) {
            ss.streaming = 1;
            ss.window = STREAM_WIN;
        }
    } else {
        ss.stride_count = 0;
        ss.streaming = 0;
        ss.window = 0;
    }
    ss.last_addr = cur_addr;
    if (ss.streaming && ss.window > 0)
        ss.window--;

    // --- Streaming bypass logic ---
    bool streaming_active = (ss.streaming && ss.window > 0);

    // --- Dead-block prediction for insertion ---
    uint8_t ins_rrpv;
    if (streaming_active) {
        // Streaming: bypass insertion (do not cache)
        // Mark block as invalid by setting RRPV to max, but do not update reuse_counter
        // (Assume simulator will not allocate block if bypass is signaled)
        ins_rrpv = RRIP_MAX;
    } else {
        // Use dead-block predictor: if previous block at victim way is dead, insert at distant
        uint8_t prev_reuse = reuse_counter[set][way];
        if (prev_reuse <= DEAD_THRESHOLD)
            ins_rrpv = RRIP_MAX;
        else if (prev_reuse == 1)
            ins_rrpv = RRIP_DISTANT;
        else
            ins_rrpv = RRIP_MRU;
    }

    if (hit) {
        rrpv[set][way] = RRIP_MRU;
        // On hit, increment reuse counter (max 3)
        if (reuse_counter[set][way] < 3)
            reuse_counter[set][way]++;
    } else {
        // On insertion, set RRPV and reset reuse counter
        rrpv[set][way] = ins_rrpv;
        if (!streaming_active)
            reuse_counter[set][way] = 1; // weakly reused
        // If streaming bypass, do not update reuse_counter
    }

    // --- Periodic decay of reuse counters ---
    if ((access_counter % DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_counter[s][w] > 0)
                    reuse_counter[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "ADSB: Streaming sets at end: " << streaming_sets << std::endl;

    // Dead-block reuse counter summary
    uint64_t dead_blocks = 0, live_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (reuse_counter[s][w] == 0)
                dead_blocks++;
            else
                live_blocks++;
    std::cout << "ADSB: Dead blocks: " << dead_blocks << ", Live blocks: " << live_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count or dead-block ratio
}