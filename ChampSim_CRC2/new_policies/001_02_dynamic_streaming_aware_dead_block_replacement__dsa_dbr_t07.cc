#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// 2 bits/line: RRPV
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 1 bit/line: dead-block flag
uint8_t dead[LLC_SETS][LLC_WAYS];

// Streaming detector: 2 bytes/set
struct StreamDetect {
    int16_t last_delta;
    uint8_t stream_count;
    bool streaming;
};
StreamDetect stream_detect[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // SRRIP distant insert
    memset(dead, 0, sizeof(dead));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        stream_detect[s].last_delta = 0;
        stream_detect[s].stream_count = 0;
        stream_detect[s].streaming = false;
    }
}

// --- Streaming detector update ---
void update_streaming(uint32_t set, uint64_t paddr) {
    int16_t delta = (int16_t)(paddr - stream_detect[set].last_delta);
    if (stream_detect[set].last_delta != 0) {
        if (delta == stream_detect[set].last_delta) {
            if (stream_detect[set].stream_count < 15)
                stream_detect[set].stream_count++;
        } else {
            if (stream_detect[set].stream_count > 0)
                stream_detect[set].stream_count--;
        }
        stream_detect[set].streaming = (stream_detect[set].stream_count >= 8);
    }
    stream_detect[set].last_delta = (int16_t)(paddr & 0xFFFF);
}

// --- Find victim: dead blocks preferred ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks for victim
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead[set][way])
            return way;
    }
    // Otherwise, SRRIP: find RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Replacement state update ---
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
    // Update streaming detector
    update_streaming(set, paddr);

    bool is_streaming = stream_detect[set].streaming;

    // On hit: mark as not dead, promote to MRU
    if (hit) {
        dead[set][way] = 0;
        rrpv[set][way] = 0;
    } else {
        // On fill: decide bypass and insertion depth
        if (is_streaming && dead[set][way]) {
            // Streaming and victim is dead: bypass (simulate by RRPV=3)
            rrpv[set][way] = 3;
        } else {
            // Dead-block: distant insert
            if (dead[set][way])
                rrpv[set][way] = 2;
            else
                rrpv[set][way] = 0;
        }
        // Mark new block as not dead
        dead[set][way] = 0;
    }

    // On eviction: if not reused, mark dead
    if (!hit) {
        // If the block was never hit since last fill, set dead bit
        if (dead[set][way] == 0)
            dead[set][way] = 1;
    }
}

// --- Stats ---
void PrintStats() {
    int dead_blocks = 0, total = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead[s][w]) dead_blocks++;
            total++;
        }
    std::cout << "DSA-DBR: Dead blocks count: " << dead_blocks << " / " << total << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_detect[s].streaming) streaming_sets++;
    std::cout << "DSA-DBR: Streaming sets: " << streaming_sets << std::endl;
}