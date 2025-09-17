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
#define SHIP_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Dead-block Approximation ---
#define DEAD_CTR_BITS 2
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- Decay State ---
#define DECAY_PERIOD 2048
uint64_t global_access_counter = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));           // Insert at distant RRPV by default
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr));   // Start at weak reuse
    memset(dead_ctr, 1, sizeof(dead_ctr));   // Start at weak reuse
    global_access_counter = 0;
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
    global_access_counter++;

    uint8_t sig = get_signature(PC);

    // --- Periodic decay of dead-block counters ---
    if (global_access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }

    // On hit: promote block, increment reuse counters
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        return;
    }

    // --- Insertion depth selection using SHiP and Dead-block counters ---
    uint8_t insertion_rrpv = 2; // default: SRRIP insert at RRPV=2

    // If either SHiP or dead-block counter is strong, insert at MRU
    if (ship_ctr[set][way] >= 2 || dead_ctr[set][way] >= 2)
        insertion_rrpv = 0;
    // If both are weak, insert at LRU (RRPV=3)
    else if (ship_ctr[set][way] == 0 && dead_ctr[set][way] == 0)
        insertion_rrpv = 3;

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1;
    dead_ctr[set][way] = 1;
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_ship = 0, strong_dead = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_ship++;
            if (dead_ctr[s][w] == 3) strong_dead++;
            total_blocks++;
        }
    }
    std::cout << "SHiP-DeadBlock Hybrid with Decayed Reuse (SHiP-DBR)" << std::endl;
    std::cout << "Blocks with strong SHiP reuse: " << strong_ship << "/" << total_blocks << std::endl;
    std::cout << "Blocks with strong dead-block reuse: " << strong_dead << "/" << total_blocks << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_ship = 0, strong_dead = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_ship++;
            if (dead_ctr[s][w] == 3) strong_dead++;
            total_blocks++;
        }
    }
    std::cout << "Strong SHiP reuse blocks (heartbeat): " << strong_ship << "/" << total_blocks << std::endl;
    std::cout << "Strong dead-block reuse blocks (heartbeat): " << strong_dead << "/" << total_blocks << std::endl;
}