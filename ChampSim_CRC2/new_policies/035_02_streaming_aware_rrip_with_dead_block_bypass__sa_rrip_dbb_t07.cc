#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//--- RRIP bits: 2 per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

//--- Dead-block: 2-bit per line, decayed periodically
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

//--- Streaming detector: last accessed address per set, last delta, simple streaming flag
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t is_streaming[LLC_SETS]; // 1 = likely streaming, 0 = not

//--- Global access counter for periodic decay
uint64_t access_count = 0;
#define DECAY_PERIOD 8192

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));         // All blocks distant
    memset(dead_ctr, 0, sizeof(dead_ctr)); // No dead predictions
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(is_streaming, 0, sizeof(is_streaming));
    access_count = 0;
}

//--------------------------------------------
// Find victim in the set (RRIP + dead-block)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks predicted dead (dead_ctr==3) and with rrpv==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 && dead_ctr[set][way] == 3)
            return way;

    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) rrpv[set][way]++;
    }
    return 0; // Should not reach
}

//--------------------------------------------
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
    access_count++;
    // Streaming detector: check address delta vs last
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    // If delta is page-aligned stride or near-sequential, likely streaming
    if (last_delta[set] != 0 && std::abs(delta) == std::abs(last_delta[set]) && (std::abs(delta) < 512*1024)) {
        is_streaming[set] = 1;
    } else {
        is_streaming[set] = 0;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    if (hit) {
        // Promote block on hit
        rrpv[set][way] = 0;
        // Block reused: dead counter decays
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
    } else {
        // Miss: decide insertion depth
        if (is_streaming[set]) {
            // Streaming detected: insert distant or bypass (simulate bypass by distant)
            rrpv[set][way] = 3;
            dead_ctr[set][way] = 3; // streaming blocks are likely dead soon
        } else {
            rrpv[set][way] = 2; // intermediate RRIP
            dead_ctr[set][way] = 2; // moderate dead prediction
        }
    }

    // Periodically decay dead counters for all blocks (aging)
    if ((access_count % DECAY_PERIOD) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Streaming-Aware RRIP with Dead-Block Bypass: Final statistics." << std::endl;
    // Optionally report streaming sets count
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (is_streaming[s]) streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[Heartbeat] Streaming sets: ";
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (is_streaming[s]) streaming_sets++;
    std::cout << streaming_sets << std::endl;
}