#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Dead-block: 2-bit counter per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// DRRIP set-dueling: 64 leader sets (32 SRRIP, 32 BRRIP), 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL; // 10 bits
uint8_t leader_type[LLC_SETS]; // 0 = normal, 1 = SRRIP leader, 2 = BRRIP leader

// Helper: assign leader sets (fixed mapping)
void AssignLeaderSets() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        leader_type[s] = 0;
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        leader_type[i] = 1; // SRRIP leader
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        leader_type[i] = 2; // BRRIP leader
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    AssignLeaderSets();
    PSEL = (1 << (PSEL_BITS - 1)); // Middle value
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Dead-block: prefer invalid or dead-predicted blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (!current_set[way].valid)
            return way;
        if (dead_ctr[set][way] == 3)
            return way;
    }
    // Standard RRIP victim search
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
}

// Update replacement state
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
    // --- DRRIP insertion policy ---
    uint8_t ins_rrpv = 2; // SRRIP default
    bool use_brrip = false;

    // Set-dueling: leader sets force policy, others use PSEL
    if (leader_type[set] == 1) { // SRRIP leader
        use_brrip = false;
    } else if (leader_type[set] == 2) { // BRRIP leader
        use_brrip = true;
    } else {
        use_brrip = (PSEL < (1 << (PSEL_BITS - 1)));
    }
    if (use_brrip)
        ins_rrpv = 3; // BRRIP: insert at distant RRPV

    // Dead-block: if predicted dead, force distant RRPV
    if (dead_ctr[set][way] == 3)
        ins_rrpv = 3;

    // On hit: promote to MRU, reset dead counter
    if (hit) {
        rrpv[set][way] = 0;
        dead_ctr[set][way] = 0;
        // Update PSEL for leader sets
        if (leader_type[set] == 1 && PSEL < ((1 << PSEL_BITS) - 1))
            PSEL++;
        if (leader_type[set] == 2 && PSEL > 0)
            PSEL--;
        return;
    }

    // On miss/fill: set RRPV and update dead counter
    rrpv[set][way] = ins_rrpv;
    // If block was evicted without reuse (i.e., rrpv==3 on fill), increment dead counter
    if (dead_ctr[set][way] < 3)
        dead_ctr[set][way]++;
    else
        dead_ctr[set][way] = 3; // saturate

    // On fill, reset dead counter if not predicted dead
    if (ins_rrpv != 3)
        dead_ctr[set][way] = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Dead-block counter histogram
    uint64_t db_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            db_hist[dead_ctr[s][w]]++;
    std::cout << "DRRIP-DBH: Dead-block counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << db_hist[i] << " ";
    std::cout << std::endl;
    std::cout << "DRRIP-DBH: PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age dead counters (avoid stuck dead prediction)
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] > 0)
                dead_ctr[s][w]--;
}