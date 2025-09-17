#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2 bits RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// DRRIP set-dueling: 64 leader sets per policy, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;
std::vector<uint32_t> srrip_leader_sets, brrip_leader_sets;

// SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024
uint8_t ship_counter[SHIP_SIG_ENTRIES]; // 2 bits per entry

// Dead-block approximation: 2 bits per line
uint8_t dead_counter[LLC_SETS][LLC_WAYS];

// Helper: get SHiP signature from PC
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2)) & ((1 << SHIP_SIG_BITS) - 1);
}

// Helper: is set a leader set?
inline bool is_srrip_leader(uint32_t set) {
    for (auto s : srrip_leader_sets) if (s == set) return true;
    return false;
}
inline bool is_brrip_leader(uint32_t set) {
    for (auto s : brrip_leader_sets) if (s == set) return true;
    return false;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // initialize to distant
    memset(ship_counter, 1, sizeof(ship_counter));
    memset(dead_counter, 0, sizeof(dead_counter));
    // Randomly select leader sets
    srrip_leader_sets.clear();
    brrip_leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        srrip_leader_sets.push_back(i);
        brrip_leader_sets.push_back(i + NUM_LEADER_SETS);
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
    // Prefer blocks with dead_counter==3 (likely dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (current_set[way].valid && dead_counter[set][way] == 3)
            return way;
    }
    // Else, SRRIP victim selection
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
    // Get SHiP signature
    uint16_t sig = get_signature(PC);

    // On hit: update SHiP and dead-block counter
    if (hit) {
        if (ship_counter[sig] < 3) ship_counter[sig]++;
        rrpv[set][way] = 0;
        if (dead_counter[set][way] > 0) dead_counter[set][way]--;
        return;
    }

    // On fill: decide insertion depth
    uint8_t ins_rrpv = 2; // default SRRIP: long but not max distant

    // SHiP: if signature counter high, bias to near insert
    if (ship_counter[sig] >= 2)
        ins_rrpv = 0; // near insert

    // Set-dueling: leader sets update PSEL
    if (is_srrip_leader(set)) {
        // SRRIP: insert at 2
        ins_rrpv = 2;
        if (hit && PSEL < PSEL_MAX) PSEL++;
    } else if (is_brrip_leader(set)) {
        // BRRIP: insert at 3 most of the time (1/32 insert at 2)
        if ((rand() % 32) == 0)
            ins_rrpv = 2;
        else
            ins_rrpv = 3;
        if (hit && ins_rrpv == 2 && PSEL > 0) PSEL--;
    } else {
        // Normal sets: choose insertion depth by PSEL
        if (PSEL >= PSEL_MAX / 2) {
            // SRRIP: insert at 2
            ins_rrpv = 2;
        } else {
            // BRRIP: insert at 3 most of the time
            if ((rand() % 32) == 0)
                ins_rrpv = 2;
            else
                ins_rrpv = 3;
        }
    }

    // Insert block
    rrpv[set][way] = ins_rrpv;
    // Dead-block counter: reset to 0 (not dead) on fill
    dead_counter[set][way] = 0;
    // SHiP: decay signature counter (weakly)
    if (ship_counter[sig] > 0) ship_counter[sig]--;
}

// --- Stats ---
void PrintStats() {
    std::cout << "DSDB-Hybrid Policy: DRRIP (SRRIP/BRRIP set-dueling) + SHiP-lite + Dead-block counter, PSEL=" << PSEL << std::endl;
}
void PrintStats_Heartbeat() {
    // Optionally print dead-block histogram
}