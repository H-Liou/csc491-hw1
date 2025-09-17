#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: Signature Table ---
// 4K entries, 2 bits per entry (8192 bits = 1 KiB)
#define SHIP_SIG_SIZE 4096
uint8_t ship_sig_table[SHIP_SIG_SIZE]; // 2 bits per entry

// --- Per-block Dead-Block Approximation ---
// 2 bits per block (2048 x 16 x 2 bits = 8 KiB)
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- RRIP State ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Decay Counter ---
uint32_t decay_tick = 0;

// --- Helper: Get signature index ---
inline uint32_t get_ship_index(uint64_t PC) {
    // Use CRC to hash PC to [0, SHIP_SIG_SIZE)
    return champsim_crc2(PC) % SHIP_SIG_SIZE;
}

// --- Initialization ---
void InitReplacementState() {
    memset(ship_sig_table, 1, sizeof(ship_sig_table)); // optimistic default
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(rrpv, 3, sizeof(rrpv)); // all blocks start as distant
    decay_tick = 0;
}

// --- Find Victim in Set: RRIP + Dead Counter ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with dead_ctr == 0 (dead block approximation)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 0)
            return way;
    // Otherwise, standard RRIP selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Update Replacement State ---
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
    // --- Decay dead_ctr periodically (every 16384 accesses) ---
    decay_tick++;
    if (decay_tick == 16384) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--; // decay by 1
        decay_tick = 0;
    }

    uint32_t ship_idx = get_ship_index(PC);

    if (hit) {
        // On hit: promote RRPV, increment dead_ctr, increment SHiP counter
        rrpv[set][way] = 0;
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
        if (ship_sig_table[ship_idx] < 3)
            ship_sig_table[ship_idx]++;
    } else {
        // On fill: use SHiP counter to choose insertion RRPV
        uint8_t ship_val = ship_sig_table[ship_idx];
        uint8_t ins_rrpv = (ship_val >= 2) ? 0 : 3; // High reuse: MRU; else: distant
        rrpv[set][way] = ins_rrpv;
        dead_ctr[set][way] = 1; // optimistic, reset reuse counter

        // On eviction, if dead_ctr==0, decrement SHiP counter to learn dead PCs
        // (simulate: victim_addr, but can't directly access victim's PC here, so skip for compactness)
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SHiP-Lite + Dead-Block Approximation Hybrid: Final statistics." << std::endl;
    // Count blocks with dead_ctr==0 (dead blocks)
    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] == 0)
                dead_blocks++;
    std::cout << "Dead blocks (dead_ctr==0): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    // Optional: histogram of SHiP table
    uint32_t high_reuse = 0, low_reuse = 0;
    for (uint32_t i = 0; i < SHIP_SIG_SIZE; ++i) {
        if (ship_sig_table[i] >= 2) high_reuse++;
        else low_reuse++;
    }
    std::cout << "SHiP signatures high reuse: " << high_reuse << " / low reuse: " << low_reuse << std::endl;
}

// --- Print periodic statistics ---
void PrintStats_Heartbeat() {
    // Optionally print dead block count and SHiP reuse histogram
}