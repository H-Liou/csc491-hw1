#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_TABLE_SIZE]; // 2-bit outcome counters

uint8_t ship_sig[LLC_SETS][LLC_WAYS]; // 6-bit PC signature per block

// Dead-block approximation: 2-bit dead counter per block
uint8_t deadctr[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // SRRIP: init to distant
    memset(ship_table, 1, sizeof(ship_table)); // Neutral outcome
    memset(ship_sig, 0, sizeof(ship_sig));
    memset(deadctr, 0, sizeof(deadctr));
}

// --- Victim selection: prefer blocks with high deadctr ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, try to evict blocks with deadctr==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (deadctr[set][way] == 3)
            return way;
    }
    // Otherwise, standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
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
    // --- SHiP-lite signature ---
    uint8_t sig = champsim_crc2(PC, 0) & SHIP_SIG_MASK;

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Positive reinforcement for SHiP outcome
        if (ship_table[sig] < 3) ++ship_table[sig];
        deadctr[set][way] = 0; // Reset dead counter
        return;
    }

    // --- On fill ---
    ship_sig[set][way] = sig;
    // Use SHiP outcome to bias insertion depth
    if (ship_table[sig] >= 2) {
        rrpv[set][way] = 0; // Insert at MRU for reused PCs
    } else {
        rrpv[set][way] = 3; // Insert at distant for cold/streaming PCs
    }
    deadctr[set][way] = 0; // Reset dead counter

    // --- On eviction: update SHiP and dead-block counters ---
    // Find victim way for this set
    uint32_t victim_way = way;
    uint8_t victim_sig = ship_sig[set][victim_way];
    // Negative reinforcement for SHiP outcome
    if (ship_table[victim_sig] > 0) --ship_table[victim_sig];
    // Increment dead counter for the block being evicted
    if (deadctr[set][victim_way] < 3) ++deadctr[set][victim_way];

    // --- Periodic decay of dead counters (every 4096 fills) ---
    static uint64_t fill_count = 0;
    ++fill_count;
    if ((fill_count & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (deadctr[s][w] > 0) --deadctr[s][w];
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SDH Policy: SHiP-lite PC-based reuse + Dead-block approximation\n";
}
void PrintStats_Heartbeat() {}