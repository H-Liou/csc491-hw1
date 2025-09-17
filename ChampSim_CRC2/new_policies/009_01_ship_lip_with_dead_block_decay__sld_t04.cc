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
uint8_t pc_sig[LLC_SETS][LLC_WAYS];      // 6 bits/block

// SHiP-lite: 64-entry outcome table (indexed by signature), 2 bits/entry
uint8_t ship_table[64]; // 2 bits per entry

// DIP: 8-bit PSEL
uint8_t PSEL = 128; // 8 bits, mid-value

// DIP: 32 leader sets (16 LIP, 16 BIP)
const uint32_t NUM_LEADER_SETS = 32;
const uint32_t LEADER_SETS_LIP = 16;
const uint32_t LEADER_SETS_BIP = 16;
bool is_leader_set_lip[LLC_SETS];
bool is_leader_set_bip[LLC_SETS];

// Dead-block approximation: 2 bits/block
uint8_t reuse_counter[LLC_SETS][LLC_WAYS]; // 2b/block

// Decay counter: global, decays reuse_counter every N fills
uint32_t decay_counter = 0;
const uint32_t DECAY_INTERVAL = 4096; // every 4096 fills

// Helper: hash PC to 6 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Assign leader sets for DIP
void AssignLeaderSets() {
    memset(is_leader_set_lip, 0, sizeof(is_leader_set_lip));
    memset(is_leader_set_bip, 0, sizeof(is_leader_set_bip));
    for (uint32_t i = 0; i < LEADER_SETS_LIP; ++i)
        is_leader_set_lip[(i * LLC_SETS) / NUM_LEADER_SETS] = true;
    for (uint32_t i = 0; i < LEADER_SETS_BIP; ++i)
        is_leader_set_bip[(i * LLC_SETS) / NUM_LEADER_SETS + 1] = true;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    memset(reuse_counter, 0, sizeof(reuse_counter));
    PSEL = 128; // midpoint
    decay_counter = 0;
    AssignLeaderSets();
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
    // Dead-block: prefer block with reuse_counter==0 and RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 && reuse_counter[set][way] == 0)
            return way;
    // Otherwise, prefer block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
    // If none, increment RRPV and retry
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
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
    // --- Dead-block decay ---
    decay_counter++;
    if (decay_counter % DECAY_INTERVAL == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_counter[s][w] > 0)
                    reuse_counter[s][w]--;
    }

    // --- SHiP-lite signature ---
    uint8_t sig = pc_hash(PC);

    // --- DIP insertion policy selection ---
    bool use_lip = false, use_bip = false;
    if (is_leader_set_lip[set]) use_lip = true;
    else if (is_leader_set_bip[set]) use_bip = true;
    else use_lip = (PSEL >= 128);

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Update SHiP outcome
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
        // Dead-block counter: increment on hit, saturate at 3
        if (reuse_counter[set][way] < 3) reuse_counter[set][way]++;
        // DIP: On hit in leader sets, increment PSEL for LIP, decrement for BIP
        if (is_leader_set_lip[set] && PSEL < 255) PSEL++;
        if (is_leader_set_bip[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- On cache miss or fill ---
    // Choose insertion RRPV
    uint8_t ins_rrpv;
    if (use_lip) {
        ins_rrpv = 3; // LRU
    } else if (use_bip) {
        // BIP: insert at LRU only every 1/32, else at MRU+1
        static uint32_t bip_counter = 0;
        if ((bip_counter++ % 32) == 0)
            ins_rrpv = 3;
        else
            ins_rrpv = 1;
    } else {
        // Dynamic: use PSEL winner
        ins_rrpv = (PSEL >= 128) ? 3 : 1;
    }

    // SHiP bias: if PC signature is frequently reused, insert at MRU
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;

    // Update block metadata
    pc_sig[set][way] = sig;
    rrpv[set][way] = ins_rrpv;
    reuse_counter[set][way] = 0; // reset on fill
    // SHiP outcome: weak initial prediction
    if (ship_table[sig] > 0) ship_table[sig]--;
    // DIP: On miss in leader sets, decrement PSEL for LIP, increment for BIP
    if (is_leader_set_lip[set] && PSEL > 0) PSEL--;
    if (is_leader_set_bip[set] && PSEL < 255) PSEL++;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Dead-block summary
    uint64_t dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            total_blocks++;
            if (reuse_counter[s][w] == 0)
                dead_blocks++;
        }
    std::cout << "SLD: Dead blocks at end: " << dead_blocks << " / " << total_blocks << std::endl;

    // SHiP table summary
    std::cout << "SLD: SHiP table (reuse counters): ";
    for (int i = 0; i < 64; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "SLD: DIP PSEL = " << (int)PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print dead block ratio or PSEL
}