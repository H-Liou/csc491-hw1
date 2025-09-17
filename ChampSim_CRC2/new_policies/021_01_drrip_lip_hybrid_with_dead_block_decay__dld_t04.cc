#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Dead-block Approximation Metadata ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Set-dueling for DRRIP/LIP ----
#define NUM_LEADER_SETS 32
uint8_t is_drrip_leader[LLC_SETS];
uint8_t is_lip_leader[LLC_SETS];
uint16_t psel; // 10 bits

// ---- Periodic decay ----
uint64_t access_count = 0;
#define DECAY_PERIOD 4096

// ---- Initialization ----
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_ctr, 1, sizeof(dead_ctr));
    memset(is_drrip_leader, 0, sizeof(is_drrip_leader));
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    psel = (1 << 9); // 512
    access_count = 0;
    // Assign leader sets: first NUM_LEADER_SETS for DRRIP, next NUM_LEADER_SETS for LIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_drrip_leader[i] = 1;
        is_lip_leader[LLC_SETS/2 + i] = 1;
    }
}

// ---- Victim selection ----
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

    // RRIP: select block with max RRPV (3), else increment all RRPV
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

// ---- Update replacement state ----
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
    access_count++;

    // ---- Dead-block counter update ----
    if (hit) {
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        rrpv[set][way] = 0; // MRU on hit
        // No further action needed
    } else {
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
    }

    // ---- Set-dueling for DRRIP/LIP ----
    uint8_t insertion_rrpv = 2; // DRRIP default: insert at distant RRPV
    bool use_lip = false;
    if (is_drrip_leader[set]) {
        use_lip = false;
    } else if (is_lip_leader[set]) {
        use_lip = true;
    } else {
        use_lip = (psel < (1 << 9)); // favor DRRIP if psel < 512
    }
    if (use_lip) {
        insertion_rrpv = 3; // LIP: always insert at farthest (max RRPV)
    } else {
        // DRRIP: 5% insert at RRPV=1, else RRPV=2
        insertion_rrpv = (rand() % 100 < 5) ? 1 : 2;
    }

    // ---- Dead-block bias: strong reuse, insert at MRU ----
    if (dead_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    rrpv[set][way] = insertion_rrpv;
    dead_ctr[set][way] = 1; // weak reuse on fill

    // ---- Set-dueling PSEL update ----
    if (is_drrip_leader[set]) {
        if (hit && psel < 1023) psel++;
    } else if (is_lip_leader[set]) {
        if (hit && psel > 0) psel--;
    }

    // ---- Periodic decay of dead-block counters ----
    if (access_count % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }
}

// ---- Print end-of-simulation statistics ----
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0, lip_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (is_lip_leader[s]) lip_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "DLD Policy: DRRIP-LIP Hybrid + Dead-Block Decay" << std::endl;
    std::cout << "Blocks with strong reuse (dead_ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "LIP leader sets: " << lip_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// ---- Print periodic (heartbeat) statistics ----
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0, lip_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (is_lip_leader[s]) lip_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "LIP leader sets (heartbeat): " << lip_sets << "/" << LLC_SETS << std::endl;
}