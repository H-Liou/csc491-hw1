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

//--- Dead-block counters: 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

//--- Streaming detector: last address per set, 8-bit delta history
uint64_t last_addr[LLC_SETS];
uint8_t delta_hist[LLC_SETS];

//--- Streaming threshold: if delta_hist saturates, treat as streaming
#define STREAM_THRESH 7

//--- Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));        // All blocks distant
    memset(dead_ctr, 1, sizeof(dead_ctr)); // Weakly dead
    memset(last_addr, 0, sizeof(last_addr));
    memset(delta_hist, 0, sizeof(delta_hist));
}

//--- Find victim in the set (SRRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
}

//--- Update replacement state
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
    //--- Streaming detector: update delta history
    uint64_t delta = (last_addr[set] == 0) ? 0 : std::abs((int64_t)paddr - (int64_t)last_addr[set]);
    last_addr[set] = paddr;
    // If delta in small range (e.g., 64B–256B), increment delta_hist
    if (delta == 64 || delta == 128 || delta == 256)
        if (delta_hist[set] < 255) delta_hist[set]++;
    else if (delta_hist[set] > 0)
        delta_hist[set]--;

    bool streaming = (delta_hist[set] >= STREAM_THRESH);

    //--- Dead-block counter update
    if (hit) {
        rrpv[set][way] = 0; // Promote on hit
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
    } else {
        // On replacement, penalize victim's dead counter
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
    }

    //--- Insertion policy
    if (streaming) {
        // Streaming: bypass with probability 1/4, else insert at distant
        static uint32_t stream_ctr = 0;
        if ((stream_ctr++ & 0x3) == 0) {
            rrpv[set][way] = 3; // Insert at distant
        } else {
            rrpv[set][way] = 3; // Or optionally, bypass (simulate by not updating block)
            // For Champsim, can't truly bypass, so insert at distant
        }
        dead_ctr[set][way] = 2; // Streaming blocks start as weakly dead
    } else {
        // Non-streaming: use dead-block counter to guide insertion
        if (dead_ctr[set][way] <= 1)
            rrpv[set][way] = 1; // Likely reused soon
        else
            rrpv[set][way] = 3; // Insert at distant
    }
}

//--- Print end-of-simulation statistics
void PrintStats() {
    // Print streaming sets and dead-block histogram
    int streaming_sets = 0, reused_blocks = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (delta_hist[set] >= STREAM_THRESH) streaming_sets++;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] <= 1) reused_blocks++;
            else dead_blocks++;
    std::cout << "SRRIP+Streaming+DeadBlock: Streaming sets: " << streaming_sets
              << ", Reused blocks: " << reused_blocks
              << ", Dead blocks: " << dead_blocks << std::endl;
}

//--- Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print number of streaming sets
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (delta_hist[set] >= STREAM_THRESH) streaming_sets++;
    std::cout << "[Heartbeat] Streaming sets: " << streaming_sets << std::endl;
}