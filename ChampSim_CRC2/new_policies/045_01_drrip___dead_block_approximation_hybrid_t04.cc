#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

// --- Parameters ---
#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // 10-bit PSEL, initialized to midpoint
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Helper: assign leader sets ---
void InitLeaderSets() {
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        leader_set_type[i] = 2; // follower
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_set_type[i] = 0; // first 64 sets: SRRIP leader
        leader_set_type[LLC_SETS - 1 - i] = 1; // last 64 sets: BRRIP leader
    }
}

// --- Replacement state initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // distant
    memset(dead_ctr, 0, sizeof(dead_ctr));
    InitLeaderSets();
    PSEL = (1 << (PSEL_BITS - 1));
}

// --- Find victim in the set ---
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

    // Dead-block approximation: prefer block with saturated dead_ctr
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;

    // Classic RRIP victim selection
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
    // --- Dead-block counter update ---
    if (hit) {
        dead_ctr[set][way] = 0; // reset on hit
        rrpv[set][way] = 0;     // protect block
    } else {
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
    }

    // --- DRRIP insertion policy ---
    uint8_t ins_rrpv;
    uint8_t set_type = leader_set_type[set];
    if (set_type == 0) { // SRRIP leader
        ins_rrpv = 2;
    } else if (set_type == 1) { // BRRIP leader
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // 1/32 probability of 2, else 3
    } else { // follower: use PSEL
        ins_rrpv = (PSEL >= (1 << (PSEL_BITS - 1))) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
    }

    // Dead-block approximation: if predicted dead, always insert at distant RRPV
    if (dead_ctr[set][way] == 3)
        rrpv[set][way] = 3;
    else
        rrpv[set][way] = ins_rrpv;

    // --- DRRIP PSEL update ---
    // Only update on hits in leader sets
    if (hit) {
        if (set_type == 0 && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        else if (set_type == 1 && PSEL > 0) PSEL--;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int protected_blocks = 0, distant_blocks = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (dead_ctr[set][way] == 3) dead_blocks++;
        }
    }
    std::cout << "DRRIP + Dead-Block Approximation Hybrid Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int protected_blocks = 0, distant_blocks = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (dead_ctr[set][way] == 3) dead_blocks++;
        }
    }
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value (heartbeat): " << PSEL << std::endl;
}