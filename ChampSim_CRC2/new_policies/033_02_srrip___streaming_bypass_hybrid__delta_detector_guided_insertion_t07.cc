#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//--------------------------------------------
// RRIP bits: 2 per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

//--------------------------------------------
// Streaming detector metadata: 2 previous address deltas per set
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_conf[LLC_SETS]; // 2-bit confidence per set

#define STREAM_CONF_MAX 3
#define STREAM_BYPASS_CONF 2 // If confidence >= 2, treat as streaming

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All blocks distant
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_conf, 0, sizeof(stream_conf));
}

//--------------------------------------------
// Find victim in the set (RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming detection: if bypass, return special value
    if (stream_conf[set] >= STREAM_BYPASS_CONF) {
        return LLC_WAYS; // Signal bypass (no block replaced)
    }
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
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
    //--- Streaming detector update
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_delta[set] != 0 && delta == last_delta[set]) {
        if (stream_conf[set] < STREAM_CONF_MAX) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    //--- Bypass logic
    if (stream_conf[set] >= STREAM_BYPASS_CONF) {
        // Streaming detected: bypass or insert at distant RRPV
        // If not a hit, don't cache (simulate bypass)
        if (!hit) {
            // No update to cache state (simulate not inserting)
            return;
        }
        // On hit, promote block
        rrpv[set][way] = 0;
        return;
    }

    //--- Standard SRRIP update
    if (hit) {
        rrpv[set][way] = 0; // Promote on hit
    } else {
        rrpv[set][way] = 2; // Insert at "long" (SRRIP: RRPV=2)
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SRRIP + Streaming Bypass Hybrid: Final statistics." << std::endl;
    // Optionally, print how many sets were streaming at end
    uint32_t streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_conf[set] >= STREAM_BYPASS_CONF)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print number of streaming sets
}