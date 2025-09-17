#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- DRRIP set-dueling ----
#define NUM_LEADER_SETS 32
uint8_t leader_sets[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP
uint16_t psel = 512; // 10-bit PSEL, neutral start (range: 0-1023)

bool IsLeaderSet(uint32_t set, uint8_t &type) {
    // Use bits [5:0] to select leader set
    uint32_t lsid = set & (NUM_LEADER_SETS - 1);
    if (lsid == 0) { type = 0; return true; } // SRRIP leader
    if (lsid == 1) { type = 1; return true; } // BRRIP leader
    return false;
}

// ---- Dead-block predictor: 2 bits per block ----
uint8_t dead_counter[LLC_SETS][LLC_WAYS]; // 2 bits per block
#define DEAD_MAX 3
#define DEAD_MIN 0
#define DEAD_DECAY_INTERVAL 4096 // Decay every 4K accesses
uint64_t global_access = 0;

// ---- Other bookkeeping ----
void InitReplacementState() {
    // RRIP
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // Default distant
            dead_counter[set][way] = 0;
        }
    // Leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        leader_sets[i] = (i == 0 ? 0 : (i == 1 ? 1 : 255));
    psel = 512;
    global_access = 0;
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Prioritize blocks predicted dead (dead_counter == DEAD_MAX)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_counter[set][way] == DEAD_MAX)
            return way;

    // RRIP: select block with max RRPV
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
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
    global_access++;

    // --- Dead-block decay: every DEAD_DECAY_INTERVAL accesses ---
    if ((global_access & (DEAD_DECAY_INTERVAL - 1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_counter[s][w] > DEAD_MIN)
                    dead_counter[s][w]--;
    }

    // --- Dead-block predictor update ---
    if (hit) {
        // On hit, block reused: reset dead counter
        dead_counter[set][way] = DEAD_MIN;
        rrpv[set][way] = 0; // Promote to MRU
    } else {
        // On miss, increment dead counter for victim
        if (dead_counter[set][way] < DEAD_MAX)
            dead_counter[set][way]++;
    }

    // --- DRRIP insertion policy ---
    uint8_t leader_type = 255;
    bool is_leader = IsLeaderSet(set, leader_type);

    uint8_t ins_rrpv = 2; // Default distant insertion
    if (is_leader) {
        // Leader set: force SRRIP or BRRIP
        if (leader_type == 0)      ins_rrpv = 2; // SRRIP: Insert at distant (2)
        else if (leader_type == 1) ins_rrpv = 3; // BRRIP: Insert at LRU (3)
    } else {
        // Follower set: pick policy based on PSEL
        if (psel >= 512) ins_rrpv = 2; // Favor SRRIP
        else             ins_rrpv = 3; // Favor BRRIP
    }

    // Dead-block override: if dead_counter saturated, always insert at LRU
    if (dead_counter[set][way] == DEAD_MAX)
        ins_rrpv = 3; // LRU

    rrpv[set][way] = ins_rrpv;

    // --- DRRIP set-dueling PSEL update ---
    if (is_leader && !hit) {
        // On miss in leader set, adjust PSEL
        if (leader_type == 0 && psel < 1023) psel++;   // SRRIP leader miss: increase PSEL
        if (leader_type == 1 && psel > 0)    psel--;   // BRRIP leader miss: decrease PSEL
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks = 0, mru_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_counter[set][way] == DEAD_MAX) dead_blocks++;
            if (rrpv[set][way] == 0) mru_blocks++;
        }
    std::cout << "DRRIP-DBP Policy: DRRIP + Dead-block Predictor Hybrid" << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "MRU blocks: " << mru_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (SRRIP-BRRIP preference): " << psel << "/1023" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_counter[set][way] == DEAD_MAX)
                dead_blocks++;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}