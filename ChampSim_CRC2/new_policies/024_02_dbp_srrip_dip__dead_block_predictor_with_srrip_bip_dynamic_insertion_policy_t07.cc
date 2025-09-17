#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Per-block: 2 bits RRPV, 2 bits dead-block predictor
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t reuse_ctr; // 2 bits: saturating counter for dead/live
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Per-set: decay epoch counter (2 bits)
uint8_t dbp_epoch[LLC_SETS];

// DIP: 64 leader sets for SRRIP, 64 for BIP
#define NUM_LEADER_SETS 64
std::vector<uint32_t> leader_srrip;
std::vector<uint32_t> leader_bip;

// PSEL: 10-bit global selector
uint16_t PSEL = 512;

// Helper: assign leader sets deterministically
void InitLeaderSets() {
    leader_srrip.clear();
    leader_bip.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_srrip.push_back(i);
        leader_bip.push_back(i + LLC_SETS/2);
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(dbp_epoch, 0, sizeof(dbp_epoch));
    InitLeaderSets();
    PSEL = 512;
}

// Find victim in the set (prefer invalid, else RRPV==3)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
                meta[set][way].rrpv++;
    }
    return 0; // Should not reach
}

// Update replacement state
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
    // --- Dead-block predictor: increment on hit, decay periodically ---
    if (hit) {
        if (meta[set][way].reuse_ctr < 3) meta[set][way].reuse_ctr++;
        meta[set][way].rrpv = 0; // promote to MRU

        // DIP update for leader sets
        bool is_leader_srrip = false, is_leader_bip = false;
        for (auto s : leader_srrip) if (set == s) is_leader_srrip = true;
        for (auto s : leader_bip)  if (set == s) is_leader_bip = true;

        if (is_leader_srrip && PSEL < 1023) PSEL++;
        if (is_leader_bip && PSEL > 0) PSEL--;

        return;
    }

    // Periodic DBP decay: every time dbp_epoch wraps (per set)
    dbp_epoch[set]++;
    if (dbp_epoch[set] >= 4) {
        dbp_epoch[set] = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (meta[set][w].reuse_ctr > 0)
                meta[set][w].reuse_ctr--;
        }
    }

    // --- DIP set-dueling: choose insertion policy ---
    bool is_leader_srrip = false, is_leader_bip = false;
    for (auto s : leader_srrip) if (set == s) is_leader_srrip = true;
    for (auto s : leader_bip)  if (set == s) is_leader_bip = true;

    uint8_t ins_rrpv = 3; // default distant

    // Dead-block predictor: insert at distant (3) if likely dead, else at 2
    if (meta[set][way].reuse_ctr == 0)
        ins_rrpv = 3;
    else
        ins_rrpv = 2;

    // Leader sets override insertion
    if (is_leader_srrip)
        ins_rrpv = 2; // SRRIP: always insert at 2
    else if (is_leader_bip)
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BIP: mostly distant, 1/32 at RRPV=2
    // Normal sets: pick policy based on PSEL
    else if (!is_leader_srrip && !is_leader_bip) {
        if (PSEL >= 512)
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BIP
    }

    // On fill: set insertion RRPV, reset reuse counter
    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].reuse_ctr = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t live = 0, dead = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].reuse_ctr >= 2) live++; else dead++;
    std::cout << "DBP-SRRIP-DIP: live blocks=" << live << ", dead blocks=" << dead << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed beyond DBP
}