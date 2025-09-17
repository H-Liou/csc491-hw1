#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-Block Approximation: 2-bit per-block reuse counter ---
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS];

// --- DRRIP set-dueling: 64 leader sets for SRRIP, 64 for BRRIP ---
#define NUM_LEADER_SETS 64
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_srrip[LLC_SETS];
bool is_leader_brrip[LLC_SETS];

// --- Periodic decay for dead-block counters ---
uint64_t global_accesses = 0;
#define DECAY_INTERVAL 4096

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // all blocks start distant
    memset(reuse_ctr, 1, sizeof(reuse_ctr)); // neutral reuse
    global_accesses = 0;

    // Assign leader sets for DRRIP set-dueling
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_srrip[s] = true, is_leader_brrip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_srrip[s] = false, is_leader_brrip[s] = true;
        else
            is_leader_srrip[s] = false, is_leader_brrip[s] = false;
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
    // RRIP victim selection: pick block with RRPV==3, else increment all and retry
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
    global_accesses++;

    // --- Periodic decay of dead-block counters ---
    if (global_accesses % DECAY_INTERVAL == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_ctr[s][w] > 0)
                    reuse_ctr[s][w]--;
    }

    // --- On hit: increment reuse counter, set RRPV to 0 ---
    if (hit) {
        if (reuse_ctr[set][way] < 3)
            reuse_ctr[set][way]++;
        rrpv[set][way] = 0;

        // DRRIP set-dueling update
        if (is_leader_srrip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_brrip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- On fill: choose insertion policy ---
    bool use_srrip = false;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_brrip[set])
        use_srrip = false;
    else
        use_srrip = (PSEL >= 512);

    // --- Dead-block approximation: if block predicted dead, insert at distant ---
    uint8_t ins_rrpv = 2; // default: SRRIP

    if (!use_srrip) {
        // BRRIP: insert at distant (3) with low probability (1/32)
        ins_rrpv = ((rand() % 32) == 0) ? 2 : 3;
    }

    // If block predicted dead (reuse_ctr==0), always insert at distant
    if (reuse_ctr[set][way] == 0)
        ins_rrpv = 3;
    else if (reuse_ctr[set][way] == 3)
        ins_rrpv = 0; // highly reused: insert at MRU

    rrpv[set][way] = ins_rrpv;
    reuse_ctr[set][way] = 1; // reset to neutral on fill
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Approximation Hybrid: Final statistics." << std::endl;
    std::cout << "PSEL = " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, dead-block counter histogram
}