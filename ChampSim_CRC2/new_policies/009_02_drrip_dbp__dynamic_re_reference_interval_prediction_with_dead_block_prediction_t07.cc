#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits/line: RRPV
uint8_t reuse_bit[LLC_SETS][LLC_WAYS];   // 1 bit/line: dead-block predictor

// --- DRRIP set-dueling: 64 leader sets, 10-bit PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t PSEL = 1 << (PSEL_BITS-1);      // PSEL counter
uint32_t leader_sets[NUM_LEADER_SETS];   // leader set indices

// --- Helper: initialize leader sets (evenly spaced) ---
void InitLeaderSets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sets[i] = (i * LLC_SETS) / NUM_LEADER_SETS;
    }
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(reuse_bit, 1, sizeof(reuse_bit)); // optimistic: all alive
    InitLeaderSets();
    PSEL = 1 << (PSEL_BITS-1); // midpoint
}

// --- Is this set a leader? ---
enum { LEADER_NONE=0, LEADER_SRRIP=1, LEADER_BRRIP=2 };
uint8_t GetLeaderType(uint32_t set) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (leader_sets[i] == set) {
            return (i % 2 == 0) ? LEADER_SRRIP : LEADER_BRRIP;
        }
    }
    return LEADER_NONE;
}

// --- Victim selection: standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find a block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // If none found, increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
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
    // Dead-block predictor: mark reuse bit
    if (hit) {
        rrpv[set][way] = 0; // promote to MRU
        reuse_bit[set][way] = 1; // mark as reused ("alive")
    } else {
        // On fill: set reuse bit to dead (0)
        reuse_bit[set][way] = 0;

        // DRRIP insertion policy
        uint8_t leader = GetLeaderType(set);

        // Determine insertion RRPV
        uint8_t ins_rrpv = 2; // Default: BRRIP (long re-reference)

        // If reuse bit from victim is alive, prefer MRU insert
        if (reuse_bit[set][way])
            ins_rrpv = 0;
        else
            ins_rrpv = 3;

        // Set-dueling leader sets
        if (leader == LEADER_SRRIP)
            ins_rrpv = 2; // SRRIP: always RRPV=2
        else if (leader == LEADER_BRRIP)
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: RRPV=2 with 1/32 probability

        // For follower sets, adapt using PSEL
        if (leader == LEADER_NONE) {
            if (PSEL >= (PSEL_MAX/2))
                ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP bias
            else
                ins_rrpv = 2; // SRRIP bias
        }
        rrpv[set][way] = ins_rrpv;
    }

    // DRRIP set-dueling feedback: update PSEL for leader sets
    uint8_t leader = GetLeaderType(set);
    if (leader == LEADER_SRRIP && !hit)
        if (PSEL < PSEL_MAX) PSEL++; // SRRIP miss: BRRIP favored
    if (leader == LEADER_BRRIP && !hit)
        if (PSEL > 0) PSEL--;        // BRRIP miss: SRRIP favored
}

// --- Stats ---
void PrintStats() {
    int dead_blocks = 0, alive_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (reuse_bit[s][w]) alive_blocks++;
            else dead_blocks++;
        }
    std::cout << "DRRIP-DBP: Alive blocks: " << alive_blocks
              << " Dead blocks: " << dead_blocks << std::endl;
    std::cout << "DRRIP-DBP: PSEL: " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "DRRIP-DBP: PSEL: " << PSEL << std::endl;
}