#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- DRRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Dead-block Reuse Counter ----
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Set-dueling for DRRIP ----
#define NUM_LEADER_SETS 32
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];
uint8_t is_lip_leader[LLC_SETS];
uint16_t psel; // 10 bits

// ---- Decay Heartbeat ----
uint64_t decay_tick = 0;
#define DECAY_PERIOD 1000000 // every 1M accesses

// ---- Initialization ----
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(reuse_ctr, 1, sizeof(reuse_ctr));
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    psel = (1 << 9); // 512
    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS/2 + i] = 1;
        is_lip_leader[LLC_SETS/4 + i] = 1;
    }
    decay_tick = 0;
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

    // DRRIP: select block with max RRPV (3), else increment all RRPV
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
    decay_tick++;
    // --- Dead-block reuse counter update ---
    if (hit) {
        if (reuse_ctr[set][way] < 3) reuse_ctr[set][way]++;
        rrpv[set][way] = 0;
    } else {
        if (reuse_ctr[set][way] > 0) reuse_ctr[set][way]--;
    }

    // --- Set-dueling for DRRIP ---
    uint8_t insertion_rrpv = 2; // SRRIP default: insert at distant RRPV
    bool use_brrip = false;
    bool use_lip = false;
    if (is_srrip_leader[set]) {
        use_brrip = false;
        use_lip = false;
    } else if (is_brrip_leader[set]) {
        use_brrip = true;
        use_lip = false;
    } else if (is_lip_leader[set]) {
        use_brrip = false;
        use_lip = true;
    } else {
        use_brrip = (psel < (1 << 9)); // favor SRRIP if psel < 512
        use_lip = false;
    }
    if (use_brrip) {
        insertion_rrpv = (rand() % 100 < 5) ? 1 : 2; // BRRIP: 5% at 1, 95% at 2
    }
    if (use_lip) {
        insertion_rrpv = 3; // LIP: always insert at LRU
    }

    // --- Dead-block bias: strong reuse, insert at MRU ---
    if (reuse_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    // Insert block
    rrpv[set][way] = insertion_rrpv;
    reuse_ctr[set][way] = 1; // weak reuse on fill

    // --- Set-dueling PSEL update ---
    if (is_srrip_leader[set]) {
        if (hit && psel < 1023) psel++;
    } else if (is_brrip_leader[set]) {
        if (hit && psel > 0) psel--;
    }

    // --- Dead-block periodic decay ---
    if (decay_tick % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_ctr[s][w] > 0)
                    reuse_ctr[s][w]--;
    }
}

// ---- Print end-of-simulation statistics ----
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0, lip_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (is_lip_leader[s]) lip_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (reuse_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "DLDD Policy: DRRIP-LIP Hybrid + Dead-Block Decay" << std::endl;
    std::cout << "Blocks with strong reuse (reuse_ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Leader sets (LIP): " << lip_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// ---- Print periodic (heartbeat) statistics ----
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0, lip_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (is_lip_leader[s]) lip_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (reuse_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "LIP leader sets (heartbeat): " << lip_sets << "/" << LLC_SETS << std::endl;
}