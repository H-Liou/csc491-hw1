#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP: 2-bit per-block RRPV ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block approximation: 2-bit per-block reuse counter ---
uint8_t reuse_counter[LLC_SETS][LLC_WAYS];

// --- Periodic decay control ---
#define DECAY_INTERVAL 4096
uint64_t access_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));           // All blocks start as distant (LRU)
    memset(reuse_counter, 1, sizeof(reuse_counter)); // Start neutral
    access_count = 0;
}

// --- Find victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection: pick block with RRPV==3, else increment all and retry
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
    access_count++;

    // --- On hit: set RRPV=0 (MRU), increment reuse counter (max 3) ---
    if (hit) {
        rrpv[set][way] = 0;
        if (reuse_counter[set][way] < 3)
            reuse_counter[set][way]++;
        return;
    }

    // --- On fill: decide insertion depth based on dead-block approximation ---
    // If line's reuse counter==0, predicted dead: insert at LRU (RRPV=3)
    // If reuse_counter>=1, insert at RRPV=1 (closer to MRU)
    uint8_t ins_rrpv = (reuse_counter[set][way] == 0) ? 3 : 1;
    rrpv[set][way] = ins_rrpv;
    reuse_counter[set][way] = 1; // Reset to neutral on fill

    // --- Periodic decay of reuse counters (global, every DECAY_INTERVAL accesses) ---
    if ((access_count & (DECAY_INTERVAL - 1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_counter[s][w] > 0)
                    reuse_counter[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SRRIP-DeadBlock Hybrid with Per-Line Reuse Counters: Final statistics." << std::endl;
    // Optionally: histogram of reuse counters, average RRPV insertion, etc.
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally: print reuse counter distribution, decay intervals, etc.
}