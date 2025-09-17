#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block predictor: 2-bit counter per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 0=live, 3=dead

// --- Streaming detector: per-set stride, monotonic counter (2 bits) ---
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];
uint8_t monotonic_count[LLC_SETS];
#define STREAM_THRESHOLD 2 // streaming if monotonic_count >= 2

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            dead_ctr[set][way] = 0;
        }
        last_addr[set] = 0;
        last_stride[set] = 0;
        monotonic_count[set] = 0;
    }
}

// Find victim in the set (SRRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
    }
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
    // --- Streaming detector update ---
    int64_t stride = (last_addr[set] == 0) ? 0 : int64_t(paddr) - int64_t(last_addr[set]);
    if (last_addr[set] != 0 && stride == last_stride[set] && stride != 0) {
        if (monotonic_count[set] < 3) monotonic_count[set]++;
    } else {
        if (monotonic_count[set] > 0) monotonic_count[set]--;
    }
    last_addr[set] = paddr;
    last_stride[set] = stride;

    // --- Streaming detection ---
    bool stream_detected = (monotonic_count[set] >= STREAM_THRESHOLD);

    if (hit) {
        // Block reused: reset dead counter, set MRU
        dead_ctr[set][way] = 0;
        rrpv[set][way] = 0;
    } else {
        // Block not reused: increment dead counter, saturate at 3
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
        // --- Streaming bypass: do not insert block if streaming detected ---
        if (stream_detected) {
            rrpv[set][way] = 3; // Insert at LRU, will be evicted soon
            return;
        }
        // --- Dead-block guided insertion ---
        if (dead_ctr[set][way] == 3) {
            // Predicted dead: insert at distant RRPV
            rrpv[set][way] = 2;
        } else {
            // Predicted live: insert at MRU
            rrpv[set][way] = 0;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks = 0, live_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead_blocks++;
            else live_blocks++;
    std::cout << "SRRIP-DBP-SB: Dead blocks: " << dead_blocks << " / "
              << (LLC_SETS * LLC_WAYS) << std::endl;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SRRIP-DBP-SB: Streaming sets: " << streaming_sets
              << " / " << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SRRIP-DBP-SB: Streaming sets: " << streaming_sets << std::endl;
}