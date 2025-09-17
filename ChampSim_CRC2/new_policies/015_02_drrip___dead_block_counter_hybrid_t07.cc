#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV per block, SRRIP vs BRRIP set-dueling ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_srrip[LLC_SETS];
bool is_leader_brrip[LLC_SETS];

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block counter: 2-bit per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 0=live, 3=dead

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // distant
    memset(dead_ctr, 0, sizeof(dead_ctr)); // live
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_srrip[s] = true, is_leader_brrip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_srrip[s] = false, is_leader_brrip[s] = true;
        else
            is_leader_srrip[s] = false, is_leader_brrip[s] = false;
    }
    PSEL = 512;
}

// --- Find victim: prioritize dead blocks, then SRRIP logic ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer victim with dead_ctr == 3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;
    // Standard SRRIP victim selection (evict line with RRPV=3)
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
    // On hit: reset dead counter, set RRPV=0 (MRU)
    if (hit) {
        dead_ctr[set][way] = 0; // observed reuse
        rrpv[set][way] = 0;
        // Set-dueling: update PSEL on leader sets
        if (is_leader_srrip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_brrip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // DRRIP policy selection: SRRIP or BRRIP insertion
    bool use_brrip = false;
    if (is_leader_srrip[set])
        use_brrip = false;
    else if (is_leader_brrip[set])
        use_brrip = true;
    else
        use_brrip = (PSEL < 512);

    // Determine insertion RRPV
    uint8_t ins_rrpv = 2; // SRRIP default: insert at RRPV=2
    if (use_brrip) {
        ins_rrpv = ((rand() % 32) == 0) ? 2 : 3; // BRRIP: mostly distant
    }

    rrpv[set][way] = ins_rrpv;

    // Dead-block counter: decay old value (eviction implies no reuse), saturate
    if (dead_ctr[set][way] < 3)
        dead_ctr[set][way]++;
    // On fill, reset dead counter if this is a new block
    if (type == 0) // Type==0: normal fill
        dead_ctr[set][way] = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Counter Hybrid: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, dead-block histogram, reuse stats
}