#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];     // 2 bits/line: RRIP value
uint8_t dbp[LLC_SETS][LLC_WAYS];      // 1 bit/line: Dead-block predictor

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 32
uint8_t is_srrip_leader[LLC_SETS];    // 1 if SRRIP leader, 0 if BRRIP leader, rest follower
uint16_t psel = 512;                  // 10-bit PSEL counter (range 0-1023)

// --- Helper: assign leader sets ---
void InitLeaderSets() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        is_srrip_leader[s] = 0;
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1; // First N are SRRIP leaders
        is_srrip_leader[LLC_SETS - 1 - i] = 2; // Last N are BRRIP leaders
    }
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(dbp, 0, sizeof(dbp));  // Not dead
    InitLeaderSets();
    psel = 512;
}

// --- Victim selection: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks for victim
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dbp[set][way] == 1)
            return way;

    // Otherwise, standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
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
    // --- Dead-block predictor update ---
    if (hit) {
        // Block was reused: mark as not dead
        dbp[set][way] = 0;
        rrpv[set][way] = 0; // Promote to MRU
    } else {
        // On fill: check DBP
        uint8_t predicted_dead = dbp[set][way];

        // DRRIP insertion policy
        uint8_t insert_rrpv;
        if (is_srrip_leader[set] == 1) {
            insert_rrpv = 2; // SRRIP: insert at RRPV=2
        } else if (is_srrip_leader[set] == 2) {
            insert_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at RRPV=2 with 1/32 probability
        } else {
            insert_rrpv = (psel >= 512) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
        }

        // If predicted dead, insert at LRU (RRPV=3)
        if (predicted_dead)
            rrpv[set][way] = 3;
        else
            rrpv[set][way] = insert_rrpv;

        dbp[set][way] = 1; // Mark as dead until proven otherwise

        // --- Set-dueling PSEL update ---
        if (is_srrip_leader[set] == 1) {
            if (hit && psel < 1023) psel++;
        } else if (is_srrip_leader[set] == 2) {
            if (hit && psel > 0) psel--;
        }
    }
}

// --- Stats ---
void PrintStats() {
    int dead_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dbp[s][w]) dead_lines++;
    std::cout << "DRRIP-DBP: Dead lines: " << dead_lines << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "DRRIP-DBP: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int dead_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dbp[s][w]) dead_lines++;
    std::cout << "DRRIP-DBP: Dead lines: " << dead_lines << std::endl;
    std::cout << "DRRIP-DBP: PSEL: " << psel << std::endl;
}