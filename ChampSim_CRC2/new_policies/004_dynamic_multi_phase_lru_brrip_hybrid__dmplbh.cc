#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// BRRIP constants
#define MAX_RRPV 3
#define LONG_RRPV 3
#define SHORT_RRPV 1
#define BRRIP_INSERT_PROB 32 // 1/32 chance for SHORT_RRPV

// Adaptive window and thresholds
#define ADAPTIVE_WINDOW 128
#define REUSE_THRESHOLD 0.25   // If >25% accesses are reuses, prefer LRU
#define STREAM_THRESHOLD 0.7   // If >70% misses, prefer BRRIP

struct SetState {
    // Replacement policy: 0 = BRRIP, 1 = LRU
    uint8_t policy;
    // Per-way RRPV for BRRIP
    uint8_t rrpv[LLC_WAYS];
    // Per-way LRU stack position (0 = MRU, LLC_WAYS-1 = LRU)
    uint8_t lru_stack[LLC_WAYS];
    // Adaptive stats
    uint32_t accesses, hits, misses, reused;
};

std::vector<SetState> sets(LLC_SETS);

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].policy = 0; // Start with BRRIP
        sets[s].accesses = sets[s].hits = sets[s].misses = sets[s].reused = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].rrpv[w] = LONG_RRPV;
            sets[s].lru_stack[w] = w; // Initialize LRU stack
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
    if (ss.policy == 0) { // BRRIP
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
    } else { // LRU
        // Find way with highest LRU stack position
        uint8_t max_stack = 0;
        uint32_t victim = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ss.lru_stack[w] >= max_stack) {
                max_stack = ss.lru_stack[w];
                victim = w;
            }
        }
        return victim;
    }
    // Should not happen
    return 0;
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
    if (hit) {
        ss.hits++;
        ss.reused++;
    } else {
        ss.misses++;
    }

    // Policy adaptation every ADAPTIVE_WINDOW accesses
    if (ss.accesses % ADAPTIVE_WINDOW == 0) {
        double reuse_rate = (double)ss.reused / ss.accesses;
        double miss_rate = (double)ss.misses / ss.accesses;
        // If streaming/irregular, prefer BRRIP
        if (miss_rate > STREAM_THRESHOLD)
            ss.policy = 0; // BRRIP
        // If high reuse, prefer LRU
        else if (reuse_rate > REUSE_THRESHOLD)
            ss.policy = 1; // LRU
        // Default: BRRIP
        else
            ss.policy = 0;
        ss.accesses = ss.hits = ss.misses = ss.reused = 0; // Reset window
    }

    // Update BRRIP state
    if (ss.policy == 0) {
        if (hit)
            ss.rrpv[way] = 0; // Promote on hit
        else {
            // Insert with LONG_RRPV most of the time, SHORT_RRPV occasionally
            if ((rand() % BRRIP_INSERT_PROB) == 0)
                ss.rrpv[way] = SHORT_RRPV;
            else
                ss.rrpv[way] = LONG_RRPV;
        }
    }

    // Update LRU state
    if (ss.policy == 1) {
        // On hit or fill, move accessed way to MRU (stack position 0), others increment if below accessed
        uint8_t accessed_pos = ss.lru_stack[way];
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (w == way)
                ss.lru_stack[w] = 0;
            else if (ss.lru_stack[w] < accessed_pos)
                ss.lru_stack[w]++;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t brrip_sets = 0, lru_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (sets[s].policy == 0) brrip_sets++; else lru_sets++;
    }
    std::cout << "BRRIP sets: " << brrip_sets << ", LRU sets: " << lru_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op or print similar info as PrintStats
}