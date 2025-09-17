#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block counter: 2 bits per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// --- DRRIP set-dueling: 32 leader sets for SRRIP, 32 for BRRIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_srrip[LLC_SETS];
bool is_leader_brrip[LLC_SETS];

// --- Periodic decay for dead-block counters ---
uint64_t access_counter = 0;
#define DECAY_PERIOD 4096

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // all blocks start distant
    memset(dead_ctr, 0, sizeof(dead_ctr));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_srrip[s] = true, is_leader_brrip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_srrip[s] = false, is_leader_brrip[s] = true;
        else
            is_leader_srrip[s] = false, is_leader_brrip[s] = false;
    }
    PSEL = 512;
    access_counter = 0;
}

// --- Find victim: prefer blocks with dead_ctr==3, else RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, look for block with dead_ctr==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;

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
    access_counter++;

    // --- On hit: set RRPV to 0, reset dead_ctr ---
    if (hit) {
        rrpv[set][way] = 0;
        dead_ctr[set][way] = 0;
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

    uint8_t ins_rrpv = 2; // SRRIP: insert at 2
    if (!use_srrip) {
        // BRRIP: insert at 3 except 1/32 fills at 2
        ins_rrpv = ((rand() % 32) == 0) ? 2 : 3;
    }
    rrpv[set][way] = ins_rrpv;
    dead_ctr[set][way] = 0; // reset on fill

    // --- On eviction: increment dead_ctr of victim block ---
    // (Assume victim_addr maps to way; if not, increment dead_ctr[set][way] here)
    // Already handled by fill above

    // --- Periodic decay of dead_ctr ---
    if ((access_counter % DECAY_PERIOD) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Hybrid DRRIP + Dead-Block Counter: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
    // Optionally print dead_ctr histogram
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print dead_ctr histogram, PSEL
}