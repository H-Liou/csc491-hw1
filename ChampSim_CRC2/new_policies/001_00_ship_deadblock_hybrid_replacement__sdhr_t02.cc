#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2 bits/line: RRPV
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 6 bits/line: PC signature
uint8_t pc_sig[LLC_SETS][LLC_WAYS];

// 1 bit/line: dead-block indicator
uint8_t dead_block[LLC_SETS][LLC_WAYS];

// SHiP table: 2K entries, 2 bits/counter
#define SHIP_TABLE_SIZE 2048
uint8_t ship_table[SHIP_TABLE_SIZE];

// Dead-block decay counter (global, for periodic decay)
uint32_t deadblock_decay_counter = 0;

// Helper: hash PC to 6 bits
inline uint8_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 11) ^ (PC >> 17)) & 0x3F;
}

// Helper: hash signature to SHiP table index
inline uint16_t ship_index(uint8_t sig) {
    return sig ^ (sig >> 3);
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // Initialize to distant
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(dead_block, 0, sizeof(dead_block));
    memset(ship_table, 1, sizeof(ship_table)); // Neutral reuse
    deadblock_decay_counter = 0;
}

// --- Victim selection: SRRIP with dead-block bias ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer to evict dead blocks first
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_block[set][way] && rrpv[set][way] == 3)
            return way;
    }
    // Standard SRRIP: find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
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
    uint8_t sig = get_signature(PC);
    uint16_t idx = ship_index(sig);

    // On hit: promote to MRU, increment SHiP counter, clear dead-block
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_table[idx] < 3)
            ship_table[idx]++;
        dead_block[set][way] = 0;
    } else {
        // On fill: decide insertion depth
        pc_sig[set][way] = sig;

        // Use both SHiP prediction and dead-block status
        uint8_t ship_score = ship_table[idx];
        bool predicted_dead = dead_block[set][way];

        if (ship_score >= 2 || !predicted_dead) {
            rrpv[set][way] = 0; // MRU insert
            dead_block[set][way] = 0;
        } else {
            rrpv[set][way] = 2; // Distant insert
            dead_block[set][way] = 1;
        }
    }

    // On eviction: decay SHiP counter if not reused, set dead-block
    if (!hit) {
        uint8_t evict_sig = pc_sig[set][way];
        uint16_t evict_idx = ship_index(evict_sig);
        if (ship_table[evict_idx] > 0)
            ship_table[evict_idx]--;
        // If line was not reused, mark as dead
        if (rrpv[set][way] == 3)
            dead_block[set][way] = 1;
    }

    // Periodic dead-block decay (every 4096 fills)
    deadblock_decay_counter++;
    if (deadblock_decay_counter % 4096 == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_block[s][w] = 0;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SDHR: SHiP table (reuse counters) summary:" << std::endl;
    int reused = 0, total = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_table[i] >= 2) reused++;
        total++;
    }
    std::cout << "High-reuse signatures: " << reused << " / " << total << std::endl;
    // Dead-block summary
    int dead = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w]) dead++;
    std::cout << "Dead blocks: " << dead << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
}

void PrintStats_Heartbeat() {
    // Print fraction of dead blocks
    int dead = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w]) dead++;
    std::cout << "SDHR: Dead blocks: " << dead << std::endl;
}