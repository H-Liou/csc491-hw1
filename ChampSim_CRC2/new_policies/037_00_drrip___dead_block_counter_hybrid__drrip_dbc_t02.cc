#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Dead-block counter: 2 bits per block ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- DRRIP set-dueling ----
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 512; // 10-bit selector, starts neutral
uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP

// ---- Leader set mapping ----
std::vector<uint32_t> leader_sets;

// ---- Periodic decay bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 8192

void InitReplacementState() {
    // RRIP and dead-block counter
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;      // Default distant insertion
            dead_ctr[set][way] = 0;  // Not dead
        }

    // Leader sets: evenly spread across LLC_SETS
    leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = (i * LLC_SETS) / NUM_LEADER_SETS;
        leader_sets.push_back(set);
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // First half SRRIP, second half BRRIP
    }

    PSEL = 512;
    access_counter = 0;
}

// Helper: is this set a leader set? Returns 0=SRRIP, 1=BRRIP, 2=Follower
uint8_t GetSetType(uint32_t set) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set)
            return leader_set_type[i];
    return 2; // Follower
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

    // Dead-block aware RRIP victim selection:
    // Prefer blocks with RRPV=3 and dead_ctr==3 (most dead), then RRPV=3, then highest dead_ctr
    uint32_t victim = LLC_WAYS;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 && dead_ctr[set][way] == 3)
            return way; // Most dead and distant

    // Next, any block with RRPV=3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            victim = way;

    if (victim != LLC_WAYS)
        return victim;

    // If none, increment RRPVs and try again
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] < 3)
            rrpv[set][way]++;

    // As a fallback, pick block with highest dead_ctr
    uint8_t max_dead = 0;
    victim = 0;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] >= max_dead) {
            max_dead = dead_ctr[set][way];
            victim = way;
        }
    return victim;
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
    access_counter++;

    // --- Dead-block counter update ---
    // On hit: block reused, reset dead_ctr
    if (hit)
        dead_ctr[set][way] = 0;
    else {
        // On miss: increment dead_ctr for victim block (if valid)
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // --- DRRIP insertion policy ---
    uint8_t set_type = GetSetType(set);
    uint8_t insert_rrpv = 2; // Default distant

    if (set_type == 0) { // SRRIP leader
        insert_rrpv = 2;
    } else if (set_type == 1) { // BRRIP leader
        insert_rrpv = (rand() % 32 == 0) ? 0 : 2; // 1/32 MRU, else distant
    } else { // Follower
        insert_rrpv = (PSEL >= 512) ? 2 : ((rand() % 32 == 0) ? 0 : 2);
    }

    // Insert block
    rrpv[set][way] = insert_rrpv;
    dead_ctr[set][way] = 0; // New block is not dead

    // --- DRRIP set-dueling update ---
    // On leader set miss, update PSEL
    if (!hit && set_type < 2) {
        if (set_type == 0 && hit == 0) {
            // SRRIP leader miss: increment PSEL
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        } else if (set_type == 1 && hit == 0) {
            // BRRIP leader miss: decrement PSEL
            if (PSEL > 0) PSEL--;
        }
    }

    // --- Periodic dead_ctr decay ---
    if ((access_counter & (DECAY_PERIOD - 1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks = 0;
    int distant_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_ctr[set][way] == 3) dead_blocks++;
            if (rrpv[set][way] == 2) distant_blocks++;
        }
    std::cout << "DRRIP-DBC Policy: DRRIP + Dead-Block Counter Hybrid" << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
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