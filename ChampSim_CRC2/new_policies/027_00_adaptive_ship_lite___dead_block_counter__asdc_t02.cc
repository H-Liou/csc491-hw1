#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block: 2-bit RRPV, 2-bit dead-block counter, 6-bit SHiP signature ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];         // 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];     // 2 bits per block
uint8_t signature[LLC_SETS][LLC_WAYS];    // 6 bits per block

// --- SHiP table: 8K entries × 2 bits = 16 KiB ---
#define SHIP_TABLE_SIZE 8192
uint8_t ship_table[SHIP_TABLE_SIZE];      // 2 bits per entry

// --- Periodic decay counter ---
uint64_t access_count = 0;
#define DECAY_PERIOD 4096 // Decay dead-block counters every 4096 accesses

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_ctr, 2, sizeof(dead_ctr)); // Start with moderate liveness
    memset(signature, 0, sizeof(signature));
    memset(ship_table, 1, sizeof(ship_table)); // Neutral initial bias
    access_count = 0;
}

// --- Helper: get SHiP signature from PC ---
inline uint8_t get_signature(uint64_t PC) {
    // 6 bits: simple hash of PC
    return (PC ^ (PC >> 8) ^ (PC >> 16)) & 0x3F;
}

// --- Helper: SHiP table index ---
inline uint32_t ship_index(uint32_t set, uint8_t sig) {
    // Use (set lower 7 bits << 6) | sig for 8K entries
    return ((set & 0x7F) << 6 | sig) & (SHIP_TABLE_SIZE - 1);
}

// --- Find victim: RRIP ---
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

    // --- SHiP signature ---
    uint8_t sig = get_signature(PC);
    uint32_t ship_idx = ship_index(set, sig);

    // --- Dead-block counter decay ---
    if (access_count % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }

    if (hit) {
        // On hit: promote block, update SHiP table, refresh dead-block counter
        rrpv[set][way] = 0;
        signature[set][way] = sig;
        if (ship_table[ship_idx] < 3) ship_table[ship_idx]++;
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        return;
    } else {
        // On miss: update SHiP table for victim block, decay dead-block counter
        uint8_t victim_sig = signature[set][way];
        uint32_t victim_idx = ship_index(set, victim_sig);
        if (ship_table[victim_idx] > 0) ship_table[victim_idx]--;
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
    }

    // --- Insertion depth logic ---
    // If block predicted dead (dead_ctr==0), insert at RRPV=3 (distant)
    // If SHiP table predicts high reuse (>=2), insert at RRPV=0 (long retention)
    // Otherwise, moderate retention (RRPV=2)
    uint8_t ins_rrpv = 2;
    if (dead_ctr[set][way] == 0) {
        ins_rrpv = 3;
    } else if (ship_table[ship_idx] >= 2) {
        ins_rrpv = 0;
    } else if (ship_table[ship_idx] == 1) {
        ins_rrpv = 2;
    } else {
        ins_rrpv = 3;
    }

    rrpv[set][way] = ins_rrpv;
    signature[set][way] = sig;
    // On fill, initialize dead-block counter to 2 (moderate liveness)
    dead_ctr[set][way] = 2;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ASDC (Adaptive SHiP-Lite + Dead-Block Counter): Final statistics." << std::endl;
    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] == 0)
                dead_blocks++;
    std::cout << "Dead blocks at end: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;

    uint32_t high_reuse = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i] >= 2)
            high_reuse++;
    std::cout << "SHiP table high-reuse entries: " << high_reuse << "/" << SHIP_TABLE_SIZE << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print dead-block histogram and SHiP table histogram
}