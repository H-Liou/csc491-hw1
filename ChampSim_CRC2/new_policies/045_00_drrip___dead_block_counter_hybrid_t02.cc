#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023 // 10 bits
uint16_t psel = PSEL_MAX / 2; // global policy selector

// Leader set assignment: first 32 sets for SRRIP, next 32 for BRRIP
bool is_leader_set[LLC_SETS];
bool is_srrip_leader[LLC_SETS];

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Periodic decay ---
uint64_t access_count = 0;
const uint64_t DECAY_PERIOD = 100000; // every 100K accesses

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // distant
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(is_leader_set, 0, sizeof(is_leader_set));
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = true;
        is_srrip_leader[i] = true; // SRRIP leaders: sets 0..31
    }
    for (uint32_t i = NUM_LEADER_SETS; i < 2*NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = true;
        is_srrip_leader[i] = false; // BRRIP leaders: sets 32..63
    }
    psel = PSEL_MAX / 2;
    access_count = 0;
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
    access_count++;
    // --- Periodic decay of dead-block counters ---
    if (access_count % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // protect block
        if (dead_ctr[set][way] > 0)
            dead_ctr[set][way]--; // block reused, decay dead counter
    }
    // --- On miss (fill) ---
    else {
        // Dead-block filtering: if dead_ctr is high, insert at distant RRPV or bypass
        if (dead_ctr[set][way] == 3) {
            rrpv[set][way] = 3; // distant (simulate bypass)
        } else {
            // DRRIP insertion policy
            bool use_srrip = false;
            if (is_leader_set[set]) {
                use_srrip = is_srrip_leader[set];
            } else {
                use_srrip = (psel >= (PSEL_MAX/2));
            }
            if (use_srrip) {
                rrpv[set][way] = 2; // SRRIP: insert at RRPV=2
            } else {
                rrpv[set][way] = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at RRPV=3, 1/32 at 2
            }
        }
        // On eviction, increment dead-block counter for victim
        uint32_t victim_way = way;
        if (dead_ctr[set][victim_way] < 3)
            dead_ctr[set][victim_way]++;
    }

    // --- DRRIP set-dueling: update PSEL on leader sets ---
    if (is_leader_set[set]) {
        // If hit, reward policy; if miss, penalize
        if (is_srrip_leader[set]) {
            if (hit && psel < PSEL_MAX) psel++;
            else if (!hit && psel > 0) psel--;
        } else {
            if (hit && psel > 0) psel--;
            else if (!hit && psel < PSEL_MAX) psel++;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int protected_blocks = 0, distant_blocks = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (dead_ctr[set][way] == 3) dead_blocks++;
        }
    }
    std::cout << "DRRIP + Dead-Block Counter Hybrid Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks (dead_ctr==3): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL: " << psel << "/" << PSEL_MAX << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int protected_blocks = 0, distant_blocks = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (dead_ctr[set][way] == 3) dead_blocks++;
        }
    }
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (heartbeat): " << psel << "/" << PSEL_MAX << std::endl;
}