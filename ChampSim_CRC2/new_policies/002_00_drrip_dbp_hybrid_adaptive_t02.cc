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

// Dead-block predictor: 2 bits per block (reuse counter)
uint8_t reuse_counter[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(reuse_counter, 1, sizeof(reuse_counter));
    srrip_leader_sets.clear();
    brrip_leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        srrip_leader_sets.push_back(i);
        brrip_leader_sets.push_back(i + NUM_LEADER_SETS);
    }
}

// --- Helper: is set a leader set? ---
inline bool is_srrip_leader(uint32_t set) {
    for (auto s : srrip_leader_sets) if (s == set) return true;
    return false;
}
inline bool is_brrip_leader(uint32_t set) {
    for (auto s : brrip_leader_sets) if (s == set) return true;
    return false;
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
    // On hit: increment reuse counter, promote block
    if (hit) {
        if (reuse_counter[set][way] < 3) reuse_counter[set][way]++;
        rrpv[set][way] = 0;
        return;
    }

    // On fill: decide insertion depth
    uint8_t ins_rrpv = 3; // default distant insert

    // Dead-block predictor: if reuse counter==0, insert at distant RRPV
    // else, insert more protectively (RRPV=2 for BRRIP, RRPV=1 for SRRIP)
    if (reuse_counter[set][way] == 0) {
        ins_rrpv = 3;
    } else {
        // DRRIP set-dueling
        if (is_srrip_leader(set)) {
            ins_rrpv = 1; // SRRIP: insert at RRPV=1
            // Update PSEL on hit
            if (hit && PSEL < PSEL_MAX) PSEL++;
        } else if (is_brrip_leader(set)) {
            ins_rrpv = (rand() % 32 == 0) ? 1 : 2; // BRRIP: mostly RRPV=2, sometimes RRPV=1
            if (hit && ins_rrpv == 1 && PSEL > 0) PSEL--;
        } else {
            // Normal sets: select by PSEL
            if (PSEL >= PSEL_MAX / 2) {
                ins_rrpv = 1; // SRRIP
            } else {
                ins_rrpv = (rand() % 32 == 0) ? 1 : 2; // BRRIP
            }
        }
    }

    // Insert block
    rrpv[set][way] = ins_rrpv;
    // Decay reuse counter (dead-block approximation)
    if (reuse_counter[set][way] > 0) reuse_counter[set][way]--;
}

// --- Stats ---
void PrintStats() {
    std::cout << "DRRIP-DBP Hybrid Adaptive: DRRIP set-dueling + per-block dead-block predictor, PSEL=" << PSEL << std::endl;
}
void PrintStats_Heartbeat() {
    // Optionally print reuse counter histogram
}