#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];  // 2 bits per block (dead-block counter)

// --- DRRIP set-dueling ---
uint16_t PSEL = 512;                   // 10-bit selector (range 0-1023)
const uint16_t PSEL_MAX = 1023;
const uint16_t PSEL_MIN = 0;

// Leader set assignment: first 32 sets for SRRIP, next 32 for BRRIP
bool is_srrip_leader(uint32_t set) { return set < 32; }
bool is_brrip_leader(uint32_t set) { return set >= 32 && set < 64; }

// Helper: periodic decay
uint64_t access_count = 0;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 3;      // Insert at distant by default
            dead_ctr[set][way] = 1;  // Neutral dead-block counter
        }
    PSEL = 512;
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

    // Prefer block with dead_ctr == 0 (likely dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 0)
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
    // --- Dead-block approximation ---
    if (hit) {
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        rrpv[set][way] = 0; // Protect reused block
    } else {
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
    }

    // --- DRRIP insertion policy ---
    // Set-dueling: leader sets update PSEL
    if (is_srrip_leader(set)) {
        // SRRIP: insert at RRPV=2 (aggressive)
        rrpv[set][way] = 2;
        if (!hit && PSEL < PSEL_MAX) PSEL++;
    } else if (is_brrip_leader(set)) {
        // BRRIP: insert at RRPV=3 (conservative, 1/32 MRU)
        rrpv[set][way] = ((rand() % 32) == 0) ? 2 : 3;
        if (!hit && PSEL > PSEL_MIN) PSEL--;
    } else {
        // Follower sets: choose policy by PSEL
        if (PSEL >= 512) {
            // SRRIP
            rrpv[set][way] = 2;
        } else {
            // BRRIP
            rrpv[set][way] = ((rand() % 32) == 0) ? 2 : 3;
        }
    }

    // --- Periodic decay of dead-block counters ---
    access_count++;
    if (access_count % (LLC_SETS * LLC_WAYS) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int live_blocks = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_ctr[set][way] == 3) live_blocks++;
            if (dead_ctr[set][way] == 0) dead_blocks++;
        }
    std::cout << "DRRIP + Dead-Block Approximation Hybrid Policy" << std::endl;
    std::cout << "Live blocks: " << live_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL: " << PSEL << " (SRRIP if >=512, BRRIP if <512)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int live_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) live_blocks++;
    std::cout << "Live blocks (heartbeat): " << live_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << std::endl;
}