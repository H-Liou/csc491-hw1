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

// --- Dead-block approximation: 2 bits per line ---
static uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 0=live, 3=dead

// --- DRRIP set-dueling: 32 leader sets for SRRIP, 32 for BRRIP ---
static const uint32_t NUM_LEADER_SETS = 64;
static const uint32_t SRRIP_LEADER_SETS = 32;
static const uint32_t BRRIP_LEADER_SETS = 32;
static uint32_t leader_sets[NUM_LEADER_SETS];
static uint16_t PSEL = 512; // 10 bits, 0=BRRIP, 1023=SRRIP

// --- Periodic decay counter for dead-block approximation ---
static uint64_t global_access_counter = 0;
static const uint64_t DECAY_PERIOD = 100000; // Decay every 100K accesses

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All lines: RRPV=3 (long re-use distance)
    memset(dead_ctr, 0, sizeof(dead_ctr));
    // Pick leader sets: evenly spaced
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        leader_sets[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
    PSEL = 512;
    global_access_counter = 0;
}

// --- DRRIP insertion policy ---
inline uint8_t DRRIP_InsertRRPV(uint32_t set) {
    // Leader sets: first half SRRIP, second half BRRIP
    for (uint32_t i = 0; i < SRRIP_LEADER_SETS; ++i)
        if (set == leader_sets[i]) return 2; // SRRIP: insert at RRPV=2
    for (uint32_t i = SRRIP_LEADER_SETS; i < NUM_LEADER_SETS; ++i)
        if (set == leader_sets[i]) return (rand() % 100 < 5) ? 2 : 3; // BRRIP: 5% at RRPV=2, else 3

    // Follower sets: use PSEL
    if (PSEL >= 512)
        return 2; // SRRIP
    else
        return (rand() % 100 < 5) ? 2 : 3; // BRRIP
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
    global_access_counter++;

    // --- Dead-block approximation ---
    if (hit) {
        // On hit: reset dead counter, promote to MRU
        dead_ctr[set][way] = 0;
        rrpv[set][way] = 0;
    } else {
        // On miss: increment dead counter (max 3)
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
    }

    // --- Periodic decay of dead counters ---
    if (global_access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }

    // --- DRRIP set-dueling update ---
    // Only update PSEL for leader sets
    bool is_leader = false;
    uint8_t leader_type = 0; // 0=SRRIP, 1=BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (set == leader_sets[i]) {
            is_leader = true;
            leader_type = (i < SRRIP_LEADER_SETS) ? 0 : 1;
            break;
        }
    }
    if (is_leader && !hit) {
        // On miss: increment/decrement PSEL
        if (leader_type == 0 && PSEL < 1023) PSEL++;
        else if (leader_type == 1 && PSEL > 0) PSEL--;
    }

    // --- Insertion policy: dead-block aware ---
    // If dead_ctr==3, insert at distant RRPV=3 (bypass effect)
    // Else, use DRRIP insertion depth
    if (!hit) {
        if (dead_ctr[set][way] == 3) {
            rrpv[set][way] = 3;
        } else {
            rrpv[set][way] = DRRIP_InsertRRPV(set);
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