#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite Metadata ---
#define SIG_BITS 6
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- Dead-block Approximation Metadata ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];           // 2 bits per block

// --- Periodic decay parameters ---
#define DECAY_INTERVAL 100000
uint64_t access_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr));
    memset(dead_ctr, 1, sizeof(dead_ctr));
    access_count = 0;
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// --- Victim selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
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

    uint8_t sig = get_signature(PC);

    // --- Decay dead-block counters periodically ---
    if (access_count % DECAY_INTERVAL == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }

    // --- SHiP update ---
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        return;
    }

    // --- Adaptive Bypass: If both SHiP and dead-block counters weak, bypass fill ---
    if (ship_ctr[set][way] <= 1 && dead_ctr[set][way] <= 1) {
        // Do not fill the block: mark as invalid (simulate bypass)
        rrpv[set][way] = 3;
        ship_signature[set][way] = sig;
        ship_ctr[set][way] = 1;
        dead_ctr[set][way] = 1;
        return;
    }

    // --- Insertion policy ---
    uint8_t insertion_rrpv = 2; // Default: SRRIP insertion

    // SHiP bias: strong reuse (ctr>=2) → insert at MRU
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    // Dead-block bias: strong reuse (ctr>=2) → insert at MRU
    if (dead_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    // Weak reuse: insert at distant RRPV (LRU)
    if (ship_ctr[set][way] <= 1 && dead_ctr[set][way] <= 1)
        insertion_rrpv = 3;

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // weak reuse on fill
    dead_ctr[set][way] = 1; // weak reuse on fill
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_ship = 0, strong_dead = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_ship++;
            if (dead_ctr[s][w] == 3) strong_dead++;
            total_blocks++;
        }
    std::cout << "SDB-AB Policy: SHiP-lite + Dead-block + Adaptive Bypass" << std::endl;
    std::cout << "Blocks with strong SHiP reuse (ctr==3): " << strong_ship << "/" << total_blocks << std::endl;
    std::cout << "Blocks with strong Dead-block reuse (ctr==3): " << strong_dead << "/" << total_blocks << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_ship = 0, strong_dead = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_ship++;
            if (dead_ctr[s][w] == 3) strong_dead++;
            total_blocks++;
        }
    std::cout << "Strong SHiP reuse blocks (heartbeat): " << strong_ship << "/" << total_blocks << std::endl;
    std::cout << "Strong Dead-block reuse blocks (heartbeat): " << strong_dead << "/" << total_blocks << std::endl;
}