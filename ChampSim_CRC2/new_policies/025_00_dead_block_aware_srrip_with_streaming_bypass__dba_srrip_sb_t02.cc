#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block RRIP (2 bits) and dead-block counter (2 bits) ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];    // 2 bits per block

// --- Streaming detector: 2 bits per set, last address/delta per set ---
uint8_t stream_ctr[LLC_SETS];            // 2 bits per set
uint64_t last_addr[LLC_SETS];
uint64_t last_delta[LLC_SETS];

// --- Periodic decay for dead-block counters ---
uint64_t access_counter = 0;
const uint64_t DECAY_PERIOD = 100000;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));         // All blocks start at distant
    memset(dead_ctr, 2, sizeof(dead_ctr)); // Start with moderate reuse
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    access_counter = 0;
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

    // --- Streaming bypass: if streaming detected, do not fill ---
    bool streaming = (stream_ctr[set] >= 2);
    if (streaming && !hit) {
        // Do not insert block; treat as bypass (no update to rrpv/dead_ctr)
        return;
    }

    // --- Dead-block counter update ---
    if (hit) {
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
        rrpv[set][way] = 0; // Promote on hit
        return;
    } else {
        // On miss: decay dead-block counter for victim block
        if (dead_ctr[set][way] > 0)
            dead_ctr[set][way]--;
    }

    // --- Insertion policy: dead-block aware ---
    uint8_t ins_rrpv = 2; // Default SRRIP insertion
    if (dead_ctr[set][way] == 0)
        ins_rrpv = 3;      // Predicted dead: insert at distant

    rrpv[set][way] = ins_rrpv;
    dead_ctr[set][way] = 1; // Reset reuse counter on fill

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
    std::cout << "DBA-SRRIP-SB: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << "/" << LLC_SETS << std::endl;

    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] == 0)
                dead_blocks++;
    std::cout << "Dead blocks at end: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and dead-block histogram
}