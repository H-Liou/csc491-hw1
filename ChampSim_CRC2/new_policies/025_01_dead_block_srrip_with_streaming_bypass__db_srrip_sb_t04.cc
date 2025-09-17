#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block: 2-bit RRPV, 2-bit dead-block counter ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];    // 2 bits per block

// --- Streaming detector: 2-bit per set, last address/delta per set ---
uint8_t stream_ctr[LLC_SETS];
uint64_t last_addr[LLC_SETS];
uint64_t last_delta[LLC_SETS];

// --- Periodic decay for dead-block counters ---
uint64_t access_counter = 0;
const uint64_t DECAY_PERIOD = 100000;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
}

// --- Find victim: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
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

    // --- Streaming detector: update on fill (miss only) ---
    if (!hit) {
        uint64_t delta = (last_addr[set] == 0) ? 0 : (paddr - last_addr[set]);
        if (last_addr[set] != 0 && delta == last_delta[set] && delta != 0) {
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
        last_delta[set] = delta;
        last_addr[set] = paddr;
    }

    // --- Per-block dead-block counter update ---
    if (hit) {
        // On hit: reset dead counter, promote block
        dead_ctr[set][way] = 0;
        rrpv[set][way] = 0;
        return;
    } else {
        // On miss: increment dead counter for victim block (if not reused)
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // --- Streaming bypass logic ---
    bool streaming = (stream_ctr[set] >= 2);
    if (streaming) {
        // Streaming detected: bypass insertion (mark block as most distant)
        rrpv[set][way] = 3;
        dead_ctr[set][way] = 0;
        return;
    }

    // --- Dead-block guided insertion depth ---
    if (dead_ctr[set][way] >= 2) {
        // Predicted dead: insert at distant RRPV=3
        rrpv[set][way] = 3;
    } else {
        // Default SRRIP: insert at RRPV=2
        rrpv[set][way] = 2;
    }
    dead_ctr[set][way] = 0;

    // --- Periodic decay for dead-block counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Dead-Block SRRIP + Streaming Bypass: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << "/" << LLC_SETS << std::endl;

    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] >= 2)
                dead_blocks++;
    std::cout << "Predicted dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and dead-block histogram
}