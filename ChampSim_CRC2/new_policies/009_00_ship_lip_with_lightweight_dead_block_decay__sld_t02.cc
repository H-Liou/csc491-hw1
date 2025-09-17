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

// Dead-block counter: 2 bits/block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// Dead-block decay: global fill counter
uint64_t global_fill_ctr = 0;
const uint64_t DECAY_INTERVAL = 4096; // Decay every 4096 fills

// BIP insertion: insert at MRU only 1/32, else at LRU
uint32_t BIP_MRU_interval = 32;
uint32_t bip_insertion_counter = 0;

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_LRU = RRIP_MAX;

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
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    memset(dead_ctr, 0, sizeof(dead_ctr));
    PSEL = 128; // midpoint
    global_fill_ctr = 0;
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
    // Prefer blocks with RRPV==RRIP_MAX and dead_ctr==3 (dead-block approximation)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX && dead_ctr[set][way] == 3)
            return way;
    // Next, prefer blocks with RRPV==RRIP_MAX
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    // If none, increment RRPV and retry
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < RRIP_MAX)
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
    global_fill_ctr++;
    if ((global_fill_ctr % DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
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
        rrpv[set][way] = RRIP_MRU;
        // Update SHiP outcome
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
        // Reset dead-block counter on reuse
        dead_ctr[set][way] = 0;
        // DIP: On hit in leader sets, increment PSEL for LIP, decrement for BIP
        if (is_leader_set_lip[set] && PSEL < 255) PSEL++;
        if (is_leader_set_bip[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- On cache miss or fill ---
    // Dead-block counter: increment on eviction
    dead_ctr[set][way]++;
    if (dead_ctr[set][way] > 3) dead_ctr[set][way] = 3;

    // Choose insertion RRPV
    uint8_t ins_rrpv;
    if (use_lip) {
        ins_rrpv = RRIP_LRU;
    } else if (use_bip) {
        // BIP: insert at MRU only every 1/32, else at LRU
        if ((bip_insertion_counter++ % BIP_MRU_interval) == 0)
            ins_rrpv = RRIP_MRU;
        else
            ins_rrpv = RRIP_LRU;
    } else {
        // Dynamic: use PSEL winner
        ins_rrpv = (PSEL >= 128) ? RRIP_LRU : RRIP_MRU;
    }

    // SHiP bias: if PC signature is frequently reused, insert at MRU
    uint8_t ship_pred = ship_table[sig];
    if (ship_pred >= 2)
        ins_rrpv = RRIP_MRU;

    // Dead-block bias: if dead_ctr==3, always insert at LRU
    if (dead_ctr[set][way] == 3)
        ins_rrpv = RRIP_LRU;

    // Update block metadata
    pc_sig[set][way] = sig;
    rrpv[set][way] = ins_rrpv;
    // SHiP outcome: weak initial prediction
    if (ship_table[sig] > 0) ship_table[sig]--;
    // DIP: On miss in leader sets, decrement PSEL for LIP, increment for BIP
    if (is_leader_set_lip[set] && PSEL > 0) PSEL--;
    if (is_leader_set_bip[set] && PSEL < 255) PSEL++;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Dead-block summary
    uint64_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] == 3)
                dead_blocks++;
    std::cout << "SLD: Dead blocks at end: " << dead_blocks << std::endl;

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
    // Optionally print dead-block count or PSEL
}