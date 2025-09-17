#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Per-block metadata: 2 bits RRPV, 2 bits reuse counter
struct BlockMeta {
    uint8_t rrpv;        // 2 bits
    uint8_t reuse_ctr;   // 2 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// DIP set-dueling: 64 leader sets for SRRIP, 64 for BIP
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

// Periodic decay: called every N fills (heartbeat)
uint64_t fill_count = 0;
void DecayReuseCounters() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].reuse_ctr > 0)
                meta[s][w].reuse_ctr--;
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    InitLeaderSets();
    PSEL = 512;
    fill_count = 0;
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
    // --- Dead-block predictor: update reuse counter ---
    if (hit) {
        meta[set][way].rrpv = 0; // promote to MRU
        if (meta[set][way].reuse_ctr < 3)
            meta[set][way].reuse_ctr++;
        // DIP set-dueling: update PSEL for leader sets
        bool is_leader_srrip = false, is_leader_bip = false;
        for (auto s : leader_srrip) if (set == s) is_leader_srrip = true;
        for (auto s : leader_bip) if (set == s) is_leader_bip = true;
        if (is_leader_srrip && PSEL < 1023) PSEL++;
        if (is_leader_bip && PSEL > 0) PSEL--;
        return;
    }

    // --- On miss/fill: choose insertion policy ---
    fill_count++;
    bool is_leader_srrip = false, is_leader_bip = false;
    for (auto s : leader_srrip) if (set == s) is_leader_srrip = true;
    for (auto s : leader_bip) if (set == s) is_leader_bip = true;

    // Dead-block prediction: if victim's reuse_ctr==0, treat as dead
    uint8_t victim_reuse = meta[set][way].reuse_ctr;
    uint8_t ins_rrpv = 3; // default distant

    if (victim_reuse == 0) {
        ins_rrpv = 3; // predicted dead: insert at distant
    } else {
        // DIP set-dueling overrides for leader sets
        if (is_leader_srrip)
            ins_rrpv = 2; // SRRIP: insert at RRPV=2
        else if (is_leader_bip)
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BIP: 1/32 at RRPV=2
        // Normal sets: pick policy based on PSEL
        else {
            if (PSEL >= 512)
                ins_rrpv = 2; // SRRIP
            else
                ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BIP
        }
    }
    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].reuse_ctr = 0; // reset reuse counter on fill

    // Periodic decay every 8192 fills
    if ((fill_count & 0x1FFF) == 0)
        DecayReuseCounters();
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t dead_blocks = 0, reused_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (meta[s][w].reuse_ctr == 0) dead_blocks++;
            if (meta[s][w].reuse_ctr >= 2) reused_blocks++;
        }
    std::cout << "DBP-SRRIP-DIP: dead_blocks=" << dead_blocks << ", reused_blocks=" << reused_blocks
              << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed here; handled in UpdateReplacementState
}