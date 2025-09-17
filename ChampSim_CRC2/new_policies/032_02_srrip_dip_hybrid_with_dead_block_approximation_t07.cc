#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//--------------------------------------------
// SRRIP RRIP bits: 2 per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// DIP leader sets/selector
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t psel = PSEL_MAX / 2; // 10-bit selector

// Leader set assignment
bool is_lip_leader[LLC_SETS] = {0};
bool is_bip_leader[LLC_SETS] = {0};

// Dead-block counter: 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

//--------------------------------------------
// Initialization
void InitReplacementState() {
    // RRIP: all distant
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way] = 3;

    // Dead-block counters: zero
    memset(dead_ctr, 0, sizeof(dead_ctr));

    // Leader set assignment
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_lip_leader[i] = true;
        is_bip_leader[LLC_SETS - 1 - i] = true;
    }
}

//--------------------------------------------
// Find victim in the set (SRRIP + dead-block bias)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, prefer blocks with dead_ctr==3 (dead-block approximation)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;

    // Otherwise, standard SRRIP: evict block with rrpv==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment all rrpv
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
}

//--------------------------------------------
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
    //--- Dead-block counter maintenance
    if (hit) {
        dead_ctr[set][way] = 0; // Reset on hit
        rrpv[set][way] = 0; // Promote on hit
    } else {
        // On insertion, determine insertion policy
        bool use_lip = false, use_bip = false;
        if (is_lip_leader[set])
            use_lip = true;
        else if (is_bip_leader[set])
            use_bip = true;
        else
            use_lip = (psel >= (PSEL_MAX / 2));

        // DIP logic: BIP inserts at distant except 1/32 times
        static uint32_t bip_ctr = 0;
        uint8_t ins_rrpv = 3;
        if (use_lip) {
            ins_rrpv = 3;
        } else if (use_bip) {
            if ((++bip_ctr & 0x1F) == 0)
                ins_rrpv = 1;
            else
                ins_rrpv = 3;
        } else {
            // Winner policy
            if (use_lip)
                ins_rrpv = 3;
            else {
                if ((++bip_ctr & 0x1F) == 0)
                    ins_rrpv = 1;
                else
                    ins_rrpv = 3;
            }
        }

        // If dead-block counter is high, force distant insertion
        if (dead_ctr[set][way] >= 2)
            ins_rrpv = 3;

        rrpv[set][way] = ins_rrpv;

        // Dead-block counter: increment if replaced, cap at 3
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;

        // DIP set-dueling: update PSEL if in leader set and miss/insert
        if (is_lip_leader[set] && !hit && psel < PSEL_MAX)
            psel++;
        if (is_bip_leader[set] && !hit && psel > 0)
            psel--;
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SRRIP-DIP Hybrid + Dead-block: Final statistics." << std::endl;
    std::cout << "Final PSEL value: " << psel << " (max " << PSEL_MAX << ")" << std::endl;
    uint32_t dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w] == 3) dead_blocks++;
            total_blocks++;
        }
    std::cout << "Dead blocks (ctr==3): " << dead_blocks << "/" << total_blocks << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print current PSEL and dead-block ratio
}