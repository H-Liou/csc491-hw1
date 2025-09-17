#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];    // 2 bits per block

// --- DRRIP metadata ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1)); // 10-bit PSEL, initialized mid-range
uint8_t leader_set_type[LLC_SETS];      // 0:SRRIP, 1:BRRIP, 2:normal

// Helper: assign leader sets (first 32 SRRIP, next 32 BRRIP)
void AssignLeaderSets() {
    for (uint32_t i = 0; i < LLC_SETS; ++i) {
        if (i < NUM_LEADER_SETS/2)
            leader_set_type[i] = 0; // SRRIP leader
        else if (i < NUM_LEADER_SETS)
            leader_set_type[i] = 1; // BRRIP leader
        else
            leader_set_type[i] = 2; // normal
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // distant
    memset(dead_ctr, 0, sizeof(dead_ctr));
    AssignLeaderSets();
    psel = (1 << (PSEL_BITS - 1));
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

    // Prefer blocks with dead_ctr==3 (likely dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;

    // Classic RRIP victim selection
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
    // --- Dead-block counter update ---
    if (hit) {
        // On hit, block is reused: reset dead counter, protect block
        dead_ctr[set][way] = 0;
        rrpv[set][way] = 0;
    } else {
        // On miss, increment dead counter (max 3)
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // --- DRRIP insertion policy ---
    uint8_t ins_rrpv = 2; // SRRIP default
    if (leader_set_type[set] == 0) {
        // SRRIP leader: always insert at RRPV=2
        ins_rrpv = 2;
    } else if (leader_set_type[set] == 1) {
        // BRRIP leader: insert at RRPV=3 with 1/32 probability, else RRPV=2
        ins_rrpv = ((rand() & 31) == 0) ? 2 : 3;
    } else {
        // Normal set: use PSEL to choose
        if (psel >= (1 << (PSEL_BITS - 1)))
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = ((rand() & 31) == 0) ? 2 : 3; // BRRIP
    }

    // On fill (miss), set insertion RRPV
    if (!hit)
        rrpv[set][way] = ins_rrpv;

    // --- PSEL update for leader sets ---
    if (leader_set_type[set] == 0) {
        // SRRIP leader: increment PSEL on hit, decrement on miss
        if (hit && psel < ((1 << PSEL_BITS) - 1)) psel++;
        else if (!hit && psel > 0) psel--;
    } else if (leader_set_type[set] == 1) {
        // BRRIP leader: decrement PSEL on hit, increment on miss
        if (hit && psel > 0) psel--;
        else if (!hit && psel < ((1 << PSEL_BITS) - 1)) psel++;
    }

    // --- Periodic dead counter decay (every 4096 fills) ---
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks = 0, protected_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_ctr[set][way] == 3) dead_blocks++;
            if (rrpv[set][way] == 0) protected_blocks++;
        }
    std::cout << "DRRIP + Dead-Block Counter Hybrid Policy" << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0, protected_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_ctr[set][way] == 3) dead_blocks++;
            if (rrpv[set][way] == 0) protected_blocks++;
        }
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value (heartbeat): " << psel << std::endl;
}