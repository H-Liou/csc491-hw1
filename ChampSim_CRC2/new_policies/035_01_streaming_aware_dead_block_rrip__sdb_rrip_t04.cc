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

//--- Dead-block counter: 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

//--- Streaming detector: 1 bit per set, track near-monotonic access
uint64_t last_addr[LLC_SETS];
uint8_t stream_flag[LLC_SETS]; // 1 if streaming detected

//--- Periodic decay counter
uint64_t global_access_ctr = 0;
#define DECAY_PERIOD 8192

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All blocks distant
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_flag, 0, sizeof(stream_flag));
    global_access_ctr = 0;
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
    global_access_ctr++;

    //--- Streaming detection: near-monotonic access
    uint64_t addr = paddr >> 6; // cache line granularity
    uint64_t delta = (last_addr[set] > addr) ? (last_addr[set] - addr) : (addr - last_addr[set]);
    if (delta == 1 || delta == 0) {
        stream_flag[set] = 1;
    } else {
        stream_flag[set] = 0;
    }
    last_addr[set] = addr;

    //--- Dead-block counter update
    if (hit) {
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
        rrpv[set][way] = 0; // promote on hit
        return;
    }

    //--- On miss: insertion logic
    if (stream_flag[set]) {
        // Streaming detected: insert distant, decay dead counter
        rrpv[set][way] = 3;
        dead_ctr[set][way] = (dead_ctr[set][way] > 0) ? (dead_ctr[set][way] - 1) : 0;
    } else {
        // Use dead-block counter to bias insertion
        if (dead_ctr[set][way] >= 2)
            rrpv[set][way] = 0; // high reuse: long retention
        else
            rrpv[set][way] = 2; // low reuse: intermediate
        // Decay on miss
        dead_ctr[set][way] = (dead_ctr[set][way] > 0) ? (dead_ctr[set][way] - 1) : 0;
    }

    //--- Periodic decay of all dead counters (every DECAY_PERIOD accesses)
    if ((global_access_ctr & (DECAY_PERIOD - 1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_ctr[s][w] = (dead_ctr[s][w] > 0) ? (dead_ctr[s][w] - 1) : 0;
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SDB-RRIP: Final statistics." << std::endl;
    // Optionally print streaming set count
    uint32_t stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_flag[s]) stream_sets++;
    std::cout << "Streaming sets (final): " << stream_sets << " / " << LLC_SETS << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[Heartbeat] Accesses: " << global_access_ctr << std::endl;
}