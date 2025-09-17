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

// Dead-block approximation: 2 bits/block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// DRRIP: 10-bit PSEL
uint16_t PSEL = 512; // 10 bits, mid-value

// DRRIP: 32 leader sets (16 SRRIP, 16 BRRIP)
const uint32_t NUM_LEADER_SETS = 32;
const uint32_t LEADER_SETS_SRRIP = 16;
const uint32_t LEADER_SETS_BRRIP = 16;
bool is_leader_set_srrip[LLC_SETS];
bool is_leader_set_brrip[LLC_SETS];

// Helper: assign leader sets for DRRIP
void AssignLeaderSets() {
    memset(is_leader_set_srrip, 0, sizeof(is_leader_set_srrip));
    memset(is_leader_set_brrip, 0, sizeof(is_leader_set_brrip));
    for (uint32_t i = 0; i < LEADER_SETS_SRRIP; ++i)
        is_leader_set_srrip[(i * LLC_SETS) / NUM_LEADER_SETS] = true;
    for (uint32_t i = 0; i < LEADER_SETS_BRRIP; ++i)
        is_leader_set_brrip[(i * LLC_SETS) / NUM_LEADER_SETS + 1] = true;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));        // All blocks start as LRU
    memset(dead_ctr, 1, sizeof(dead_ctr)); // Weakly alive
    PSEL = 512; // midpoint
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
    // Standard RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
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
    // --- Dead-block counter update ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        // DRRIP: On hit in leader sets, increment/decrement PSEL
        if (is_leader_set_srrip[set] && PSEL < 1023) PSEL++;
        if (is_leader_set_brrip[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- On cache miss or fill ---
    // DRRIP winner selection
    bool use_srrip = false, use_brrip = false;
    if (is_leader_set_srrip[set]) use_srrip = true;
    else if (is_leader_set_brrip[set]) use_brrip = true;
    else use_srrip = (PSEL >= 512);

    // Dead-block informed insertion depth
    uint8_t ins_rrpv;
    if (dead_ctr[set][way] == 0) {
        // Predicted dead: insert at LRU (RRIP=3)
        ins_rrpv = 3;
    } else if (use_srrip) {
        // SRRIP: insert at intermediate (RRIP=2)
        ins_rrpv = 2;
    } else if (use_brrip) {
        // BRRIP: insert at LRU (RRIP=3) with low probability (1/32), else at intermediate
        static uint32_t brrip_counter = 0;
        if ((brrip_counter++ % 32) == 0)
            ins_rrpv = 3;
        else
            ins_rrpv = 2;
    } else {
        // Dynamic: use PSEL winner
        ins_rrpv = (PSEL >= 512) ? 2 : 3;
    }

    // If recently reused (dead_ctr==3), insert at MRU (RRIP=0)
    if (dead_ctr[set][way] == 3)
        ins_rrpv = 0;

    // Update block metadata
    rrpv[set][way] = ins_rrpv;
    dead_ctr[set][way] = 1; // On fill, weakly alive

    // DRRIP: On miss in leader sets, decrement/increment PSEL
    if (is_leader_set_srrip[set] && PSEL > 0) PSEL--;
    if (is_leader_set_brrip[set] && PSEL < 1023) PSEL++;

    // --- Periodic dead-block decay (every 4096 fills) ---
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) { // Every 4096 fills
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Dead-block summary
    uint64_t dead_blocks = 0, total_blocks = LLC_SETS * LLC_WAYS;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] == 0)
                dead_blocks++;
    std::cout << "DBI-DRRIP: Dead blocks at end: " << dead_blocks << " / " << total_blocks << std::endl;

    // Print PSEL value
    std::cout << "DBI-DRRIP: DRRIP PSEL = " << (int)PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print dead block ratio or PSEL
}