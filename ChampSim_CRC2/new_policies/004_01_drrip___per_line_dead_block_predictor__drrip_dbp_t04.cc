#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;
uint8_t is_leader_set[LLC_SETS]; // 0: not leader, 1: SRRIP leader, 2: BRRIP leader

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Per-line Dead Block Predictor (DBP) ---
uint8_t dead_counter[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_counter, 0, sizeof(dead_counter));
    memset(is_leader_set, 0, sizeof(is_leader_set));
    // Assign leader sets: first half SRRIP, second half BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = 1; // SRRIP leader
        is_leader_set[LLC_SETS - 1 - i] = 2; // BRRIP leader
    }
}

// --- Find victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Standard RRIP victim selection
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
    // --- Dead Block Predictor update ---
    if (hit) {
        // On hit: promote block, reset dead counter
        rrpv[set][way] = 0;
        dead_counter[set][way] = 0;
        // DRRIP set-dueling: update PSEL for leader sets
        if (is_leader_set[set] == 1) { // SRRIP leader
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (is_leader_set[set] == 2) { // BRRIP leader
            if (PSEL > 0) PSEL--;
        }
        return;
    } else {
        // On miss: increment dead counter (max 3)
        if (dead_counter[set][way] < 3) dead_counter[set][way]++;
    }

    // --- DRRIP insertion policy ---
    uint8_t ins_rrpv = 2; // SRRIP default: insert at RRPV=2
    if (is_leader_set[set] == 2) {
        // BRRIP leader: insert at RRPV=3 with 1/32 probability, else RRPV=2
        ins_rrpv = ((rand() & 0x1F) == 0) ? 3 : 2;
    } else if (is_leader_set[set] == 1) {
        // SRRIP leader: always RRPV=2
        ins_rrpv = 2;
    } else {
        // Follower: use PSEL to pick SRRIP or BRRIP
        if (PSEL >= PSEL_MAX / 2)
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = ((rand() & 0x1F) == 0) ? 3 : 2; // BRRIP
    }

    // --- Dead Block Prediction: override insertion ---
    if (dead_counter[set][way] >= 2) {
        // If predicted dead, insert at distant RRPV or bypass with 1/16 probability
        if ((rand() & 0xF) == 0) {
            // Bypass: mark block as invalid (simulate not allocating)
            rrpv[set][way] = 3;
            return;
        } else {
            rrpv[set][way] = 3;
            return;
        }
    }

    // Normal insertion
    rrpv[set][way] = ins_rrpv;
}

// --- Periodic decay of dead counters (called every N million accesses) ---
void DecayDeadCounters() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_counter[s][w] > 0) dead_counter[s][w]--;
}

// --- Stats ---
void PrintStats() {
    int dead_lines = 0, total_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_counter[s][w] >= 2) dead_lines++;
            total_lines++;
        }
    std::cout << "DRRIP-DBP Policy: DRRIP + Per-Line Dead Block Predictor" << std::endl;
    std::cout << "Dead lines detected: " << dead_lines << "/" << total_lines << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print PSEL and dead line statistics
    int dead_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_counter[s][w] >= 2) dead_lines++;
    std::cout << "Heartbeat: dead lines " << dead_lines << ", PSEL " << PSEL << std::endl;
}