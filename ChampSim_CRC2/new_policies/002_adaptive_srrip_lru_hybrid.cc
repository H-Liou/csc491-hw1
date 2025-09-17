#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP constants
#define MAX_RRPV 3
#define INIT_RRPV 2

// Adaptive threshold for switching
#define ADAPTIVE_WINDOW 128
#define MISS_THRESHOLD 0.35

struct SetState {
    // Replacement policy: 0 = LRU, 1 = SRRIP
    uint8_t policy;
    // Per-way LRU stack position
    uint8_t lru_stack[LLC_WAYS];
    // Per-way RRPV
    uint8_t rrpv[LLC_WAYS];
    // Adaptive stats
    uint32_t hits, misses, accesses;
};

std::vector<SetState> sets(LLC_SETS);

void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].policy = 0; // Start with LRU
        sets[s].hits = sets[s].misses = sets[s].accesses = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].lru_stack[w] = w;
            sets[s].rrpv[w] = INIT_RRPV;
        }
    }
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
    SetState &ss = sets[set];
    if (ss.policy == 0) { // LRU
        // Find way with max lru_stack value
        uint8_t max_pos = 0;
        uint32_t victim = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ss.lru_stack[w] >= max_pos) {
                max_pos = ss.lru_stack[w];
                victim = w;
            }
        }
        return victim;
    } else { // SRRIP
        // Find block with MAX_RRPV
        while (true) {
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (ss.rrpv[w] == MAX_RRPV)
                    return w;
            }
            // Increment all RRPVs (aging)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (ss.rrpv[w] < MAX_RRPV)
                    ss.rrpv[w]++;
        }
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
    SetState &ss = sets[set];
    ss.accesses++;
    if (hit) ss.hits++; else ss.misses++;

    // Policy adaptation every ADAPTIVE_WINDOW accesses
    if (ss.accesses % ADAPTIVE_WINDOW == 0) {
        double miss_rate = (double)ss.misses / ss.accesses;
        if (miss_rate > MISS_THRESHOLD) ss.policy = 1; // SRRIP
        else ss.policy = 0; // LRU
        ss.hits = ss.misses = ss.accesses = 0; // Reset window
    }

    // Update LRU stack
    if (ss.policy == 0) {
        uint8_t accessed_pos = ss.lru_stack[way];
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ss.lru_stack[w] < accessed_pos)
                ss.lru_stack[w]++;
        }
        ss.lru_stack[way] = 0;
    }

    // Update SRRIP state
    if (ss.policy == 1) {
        if (hit)
            ss.rrpv[way] = 0; // Promote on hit
        else
            ss.rrpv[way] = INIT_RRPV; // Insert with INIT_RRPV on miss
    }
}

void PrintStats() {
    // Optional: Print policy distribution
    uint32_t lru_sets = 0, srrip_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (sets[s].policy == 0) lru_sets++; else srrip_sets++;
    }
    std::cout << "LRU sets: " << lru_sets << ", SRRIP sets: " << srrip_sets << std::endl;
}

void PrintStats_Heartbeat() {
    // Optional: print nothing or similar info as PrintStats
}