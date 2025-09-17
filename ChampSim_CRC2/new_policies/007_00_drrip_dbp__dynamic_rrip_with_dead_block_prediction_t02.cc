#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits/line
uint8_t dbp[LLC_SETS][LLC_WAYS];         // 2 bits/line: dead-block predictor

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 64
uint8_t is_srrip_leader[LLC_SETS]; // 1 if SRRIP leader, 2 if BRRIP leader, 0 otherwise
uint16_t psel = 512; // 10-bit PSEL, initialized to midpoint

// --- Periodic decay for DBP ---
uint64_t access_counter = 0;
#define DBP_DECAY_PERIOD 100000

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(dbp, 0, sizeof(dbp));   // DBP counters to 0 (unknown)
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    psel = 512;
    access_counter = 0;

    // Assign leader sets: first 32 SRRIP, next 32 BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        is_srrip_leader[i] = 1;
    for (uint32_t i = NUM_LEADER_SETS; i < 2 * NUM_LEADER_SETS; ++i)
        is_srrip_leader[i] = 2;
}

// --- Victim selection: prioritize dead blocks ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, try to evict a dead block (dbp == 0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dbp[set][way] == 0)
            return way;
    }
    // Otherwise, standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
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
    access_counter++;

    // --- Dead-block predictor update ---
    if (hit) {
        // Mark as reused
        if (dbp[set][way] < 3) dbp[set][way]++;
        // Promote to MRU
        rrpv[set][way] = 0;
    } else {
        // On fill, reset DBP counter
        dbp[set][way] = 1; // weakly alive

        // --- DRRIP insertion policy ---
        bool use_srrip = false;
        if (is_srrip_leader[set] == 1)
            use_srrip = true;
        else if (is_srrip_leader[set] == 2)
            use_srrip = false;
        else
            use_srrip = (psel >= 512);

        // SRRIP: insert at RRPV=2; BRRIP: insert at RRPV=3 (1/32 fills at RRPV=2)
        uint8_t ins_rrpv = 2;
        if (!use_srrip) {
            if ((rand() % 32) == 0)
                ins_rrpv = 2;
            else
                ins_rrpv = 3;
        }

        rrpv[set][way] = ins_rrpv;

        // --- DRRIP set-dueling feedback ---
        if (is_srrip_leader[set] == 1 && hit)
            if (psel < 1023) psel++;
        if (is_srrip_leader[set] == 2 && hit)
            if (psel > 0) psel--;
    }

    // --- Periodic DBP decay: every DBP_DECAY_PERIOD accesses, decay all counters ---
    if ((access_counter % DBP_DECAY_PERIOD) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dbp[s][w] > 0) dbp[s][w]--;
    }
}

// --- Stats ---
void PrintStats() {
    int dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dbp[s][w] == 0) dead_blocks++;
            total_blocks++;
        }
    std::cout << "DRRIP-DBP: Dead blocks: " << dead_blocks << " / " << total_blocks << std::endl;
    std::cout << "DRRIP-DBP: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "DRRIP-DBP: PSEL: " << psel << std::endl;
}