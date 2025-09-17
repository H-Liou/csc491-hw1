#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 6-bit PC signature per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 6 bits/block

// SHiP-lite: 64-entry outcome table (indexed by signature), 2 bits/entry
uint8_t ship_table[64];

// DRRIP: 10-bit PSEL counter
uint16_t PSEL = 512;

// DIP-style set-dueling: 64 leader sets for SRRIP, 64 for BRRIP
const uint32_t NUM_LEADER_SETS = 64;
std::vector<uint32_t> leader_sets_srrip;
std::vector<uint32_t> leader_sets_brrip;

// Helper: hash PC to 6 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused

    // Select leader sets for SRRIP and BRRIP (non-overlapping)
    leader_sets_srrip.clear();
    leader_sets_brrip.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sets_srrip.push_back(i);
        leader_sets_brrip.push_back(i + NUM_LEADER_SETS);
    }
    PSEL = 512; // midpoint
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Dead-block preference: prefer blocks with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
    // If none, increment RRPV and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] < 3)
            rrpv[set][way]++;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
    return 0;
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
    uint8_t sig = pc_hash(PC);

    // Determine if this set is a leader set
    bool is_leader_srrip = std::find(leader_sets_srrip.begin(), leader_sets_srrip.end(), set) != leader_sets_srrip.end();
    bool is_leader_brrip = std::find(leader_sets_brrip.begin(), leader_sets_brrip.end(), set) != leader_sets_brrip.end();

    // --- SHiP-lite prediction ---
    uint8_t ship_pred = ship_table[sig];

    // --- DRRIP insertion policy selection ---
    // SRRIP: insert at RRPV=2 (near-MRU)
    // BRRIP: insert at RRPV=3 (distant) with 1/32 probability, else RRPV=2
    uint8_t ins_rrpv = 2;
    if (is_leader_srrip) {
        ins_rrpv = 2;
    } else if (is_leader_brrip) {
        ins_rrpv = (rand() % 32 == 0) ? 3 : 2;
    } else {
        // Non-leader sets: use PSEL to choose
        if (PSEL >= 512)
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 3 : 2; // BRRIP
    }

    // --- SHiP-lite bias ---
    // If SHiP predicts strong reuse, insert at MRU (RRPV=0)
    if (ship_pred >= 2)
        ins_rrpv = 0;

    if (hit) {
        rrpv[set][way] = 0; // promote to MRU
        // Positive reinforcement for SHiP
        if (ship_table[pc_sig[set][way]] < 3)
            ship_table[pc_sig[set][way]]++;
    } else {
        // On insertion, set signature and RRIP value
        pc_sig[set][way] = sig;
        rrpv[set][way] = ins_rrpv;
    }

    // --- DIP-style set-dueling feedback ---
    // On miss in leader sets, update PSEL
    if (!hit) {
        if (is_leader_srrip && ins_rrpv == 2)
            if (PSEL < 1023) PSEL++;
        if (is_leader_brrip && (ins_rrpv == 3 || ins_rrpv == 2))
            if (PSEL > 0) PSEL--;
    }

    // --- SHiP-lite negative reinforcement ---
    // On eviction of a block that was not reused, penalize its signature
    if (!hit && victim_addr != 0) {
        uint8_t victim_sig = pc_sig[set][way];
        if (ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP-SHIP-DIP: Final PSEL = " << PSEL << std::endl;
    std::cout << "DRRIP-SHIP-DIP: SHiP table (reuse counters): ";
    for (int i = 0; i < 64; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL or SHiP table summary
}