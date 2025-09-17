#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// Set-dueling: 32 leader sets for SRRIP, 32 for BRRIP
static const uint32_t NUM_LEADER_SETS = 64;
static uint32_t leader_sets[NUM_LEADER_SETS];
static uint8_t leader_policy[NUM_LEADER_SETS]; // 0=SRRIP, 1=BRRIP
static uint16_t PSEL = 512; // 10 bits, range 0-1023

// --- Dead-block approximation ---
static uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Periodic decay counter ---
static uint64_t access_count = 0;
static const uint64_t DECAY_PERIOD = 100000; // Decay every 100K accesses

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All lines: RRPV=3 (long re-use distance)
    memset(dead_ctr, 0, sizeof(dead_ctr));
    // Assign leader sets: first 32 for SRRIP, next 32 for BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sets[i] = (i * LLC_SETS) / NUM_LEADER_SETS;
        leader_policy[i] = (i < NUM_LEADER_SETS/2) ? 0 : 1;
    }
    PSEL = 512;
    access_count = 0;
}

// --- Find victim (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
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
    // Decay dead-block counters periodically
    if (access_count % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }

    // --- Dead-block update ---
    if (hit) {
        rrpv[set][way] = 0; // Promote to MRU
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
        return;
    }

    // On eviction: increment dead-block counter for victim
    if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;

    // --- DRRIP insertion policy ---
    // Is this set a leader set?
    uint8_t policy = 0; // Default to SRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (set == leader_sets[i]) {
            policy = leader_policy[i];
            break;
        }
    }
    // For non-leader sets, use PSEL to select policy
    if (policy == 0 && set >= leader_sets[0] && set <= leader_sets[NUM_LEADER_SETS-1]) {
        // Already set by leader
    } else {
        policy = (PSEL >= 512) ? 0 : 1; // SRRIP if PSEL high, else BRRIP
    }

    // Dead-block: if dead confidence high, insert at RRPV=3 (bypass effect)
    if (dead_ctr[set][way] == 3) {
        rrpv[set][way] = 3;
        return;
    }

    // DRRIP insertion
    if (policy == 0) {
        // SRRIP: insert at RRPV=2
        rrpv[set][way] = 2;
    } else {
        // BRRIP: insert at RRPV=3 with low probability (1/32), else RRPV=2
        if ((rand() & 31) == 0)
            rrpv[set][way] = 3;
        else
            rrpv[set][way] = 2;
    }

    // --- Leader set feedback ---
    // If this is a leader set, update PSEL based on hit/miss
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (set == leader_sets[i]) {
            if (leader_policy[i] == 0) {
                // SRRIP leader: increment PSEL on hit, decrement on miss
                if (hit && PSEL < 1023) PSEL++;
                else if (!hit && PSEL > 0) PSEL--;
            } else {
                // BRRIP leader: decrement PSEL on hit, increment on miss
                if (hit && PSEL > 0) PSEL--;
                else if (!hit && PSEL < 1023) PSEL++;
            }
            break;
        }
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DRRIP-DBA Policy: DRRIP + Dead-Block Approximation\n";
    // Dead-block counter histogram
    uint32_t dead_hist[4] = {0,0,0,0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            dead_hist[dead_ctr[s][w]]++;
    std::cout << "Dead-block counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << dead_hist[i] << " ";
    std::cout << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {}