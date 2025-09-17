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

// Per-block dead-block approximation counter (2 bits)
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// Per-block PC signature (6 bits)
uint8_t pc_sig[LLC_SETS][LLC_WAYS];

// SHiP outcome table: 64 entries, 2 bits each
#define SHIP_TABLE_SIZE 64
uint8_t ship_table[SHIP_TABLE_SIZE];

// Decay interval for dead counters
#define DEAD_DECAY_INTERVAL 8192
uint64_t access_count = 0;

// Helper: get 6-bit PC signature
inline uint8_t GetPCSig(uint64_t PC) {
    // Use CRC or simple hash
    return (champsim_crc2(PC, 0) ^ (PC >> 2)) & 0x3F;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(dead_ctr, 2, sizeof(dead_ctr)); // mid value
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // neutral reuse
    access_count = 0;
}

// --- Victim selection: Standard SRRIP ---
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
    ++access_count;

    // Decay dead counters periodically (approximate dead-block)
    if ((access_count & (DEAD_DECAY_INTERVAL-1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) --dead_ctr[s][w];
    }

    uint8_t sig = GetPCSig(PC);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Mark block as reused
        if (dead_ctr[set][way] < 3) ++dead_ctr[set][way];
        // Train SHiP outcome table
        if (ship_table[sig] < 3) ++ship_table[sig];
        pc_sig[set][way] = sig;
        return;
    }

    // --- On fill ---
    // Dead-block approximation: bypass fill if block was not reused recently
    if (dead_ctr[set][way] == 0) {
        rrpv[set][way] = 3; // Insert at distant RRPV (effectively bypass)
        pc_sig[set][way] = sig;
        dead_ctr[set][way] = 1; // Reset to low reuse
        return;
    }

    // Use SHiP outcome table to bias insertion depth
    uint8_t reuse_score = ship_table[sig];
    if (reuse_score >= 2) {
        // High reuse: insert at MRU
        rrpv[set][way] = 0;
    } else if (reuse_score == 1) {
        // Moderate reuse: insert at mid-RRPV
        rrpv[set][way] = 2;
    } else {
        // Low reuse: insert at distant RRPV
        rrpv[set][way] = 3;
    }

    pc_sig[set][way] = sig;
    dead_ctr[set][way] = 1; // Reset to low reuse

    // --- Train SHiP outcome table on victim ---
    // If victim block was not reused, decrement outcome
    uint8_t victim_sig = pc_sig[set][way];
    if (dead_ctr[set][way] == 1 && ship_table[victim_sig] > 0)
        --ship_table[victim_sig];
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SDH Policy: SHiP-lite PC signature + Dead-block approximation\n";
}
void PrintStats_Heartbeat() {}