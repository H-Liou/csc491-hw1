#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];           // 2 bits per block
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;
std::vector<uint32_t> srrip_leader_sets, brrip_leader_sets;

// --- SHiP-lite metadata ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024
uint8_t ship_counter[SHIP_SIG_ENTRIES];     // 2 bits per entry

// --- Dead-block approximation ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];       // 2 bits per block

// --- Helper: get SHiP signature from PC ---
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2)) & ((1 << SHIP_SIG_BITS) - 1);
}

// --- Helper: leader sets ---
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
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_counter, 1, sizeof(ship_counter));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    srrip_leader_sets.clear();
    brrip_leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        srrip_leader_sets.push_back(i);
        brrip_leader_sets.push_back(i + NUM_LEADER_SETS);
    }
    PSEL = PSEL_MAX / 2;
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
    // Dead-block hint: try to evict blocks with dead_ctr==0 first
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 0 && rrpv[set][way] == 3)
            return way;

    // Standard SRRIP victim selection
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
    uint16_t sig = get_signature(PC);

    // On hit: update SHiP and deadblock counter
    if (hit) {
        if (ship_counter[sig] < 3) ship_counter[sig]++;
        rrpv[set][way] = 0;
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        return;
    }

    // --- Choose insertion depth ---
    uint8_t ins_rrpv = 3; // default distant

    // SHiP bias: if signature shows reuse, use near insert
    if (ship_counter[sig] >= 2)
        ins_rrpv = 1;
    else
        ins_rrpv = 3;

    // Dead-block: if block showed little recent reuse, prefer distant insertion
    if (dead_ctr[set][way] == 0)
        ins_rrpv = 3;

    // DRRIP set-dueling for insertion policy
    if (is_srrip_leader(set)) {
        ins_rrpv = 1; // SRRIP: insert at 1
        if (hit && PSEL < PSEL_MAX) PSEL++;
    } else if (is_brrip_leader(set)) {
        ins_rrpv = ((rand() % 32) == 0) ? 1 : 3; // BRRIP: mostly distant
        if (hit && ins_rrpv == 1 && PSEL > 0) PSEL--;
    } else {
        // Normal sets: choose by PSEL
        if (PSEL >= PSEL_MAX / 2) {
            ins_rrpv = 1; // SRRIP
        } else {
            ins_rrpv = ((rand() % 32) == 0) ? 1 : 3; // BRRIP
        }
    }

    // Insert block
    rrpv[set][way] = ins_rrpv;
    ship_counter[sig] = (ship_counter[sig] > 0) ? ship_counter[sig] - 1 : 0;
    dead_ctr[set][way] = 0; // reset dead-block counter
}

// --- Stats ---
void PrintStats() {
    std::cout << "DSDA Policy: DRRIP (SRRIP/BRRIP set-dueling) + SHiP-lite + Deadblock, PSEL=" << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print dead-block counter histogram
}