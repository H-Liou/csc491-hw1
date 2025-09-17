#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Dead-block Counter Metadata ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- DRRIP Set-dueling ----
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 512; // 10-bit selector, starts neutral
uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP

std::vector<uint32_t> leader_sets;

// Helper: is this set a leader set? Returns 0=SRRIP, 1=BRRIP, 2=Follower
uint8_t GetSetType(uint32_t set) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set)
            return leader_set_type[i];
    return 2; // Follower
}

void InitReplacementState() {
    // RRIP and dead-block counter
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // Default distant
            dead_ctr[set][way] = 0;
        }
    }
    // Leader sets: evenly spread across LLC_SETS
    leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = (i * LLC_SETS) / NUM_LEADER_SETS;
        leader_sets.push_back(set);
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // First half SRRIP, second half BRRIP
    }
    PSEL = 512;
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

    // RRIP victim selection: prefer RRPV=3, then increment RRPVs
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
        dead_ctr[set][way] = 0; // Reset on hit
    } else {
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // --- Set-dueling: leader sets update PSEL ---
    uint8_t set_type = GetSetType(set);
    if (!hit && set_type < 2) {
        if (set_type == 0) { // SRRIP leader miss: increment PSEL
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        } else if (set_type == 1) { // BRRIP leader miss: decrement PSEL
            if (PSEL > 0) PSEL--;
        }
    }

    // --- Insertion policy ---
    uint8_t insert_rrpv = 2; // Default distant
    if (dead_ctr[set][way] == 3) {
        // Block is likely dead: insert at distant RRPV
        insert_rrpv = 3;
    } else {
        // DRRIP insertion: SRRIP (RRPV=2) or BRRIP (mostly RRPV=2, sometimes RRPV=3)
        bool use_brrip = false;
        if (set_type == 0) { // SRRIP leader
            use_brrip = false;
        } else if (set_type == 1) { // BRRIP leader
            use_brrip = true;
        } else { // Follower
            use_brrip = (PSEL < 512);
        }
        if (use_brrip) {
            // BRRIP: insert at RRPV=3 with low probability (e.g., 1/32), else RRPV=2
            if ((rand() & 31) == 0)
                insert_rrpv = 3;
            else
                insert_rrpv = 2;
        } else {
            // SRRIP: always insert at RRPV=2
            insert_rrpv = 2;
        }
    }
    rrpv[set][way] = insert_rrpv;
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead_blocks++;
    std::cout << "DRRIP-DBC Policy: DRRIP + Dead-Block Counter Hybrid" << std::endl;
    std::cout << "Dead blocks (counter=3): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead_blocks++;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}