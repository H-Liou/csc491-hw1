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
#define STREAM_THRESHOLD 0.7   // If >70% misses are not reused, prefer FIFO

struct SetState {
    // Replacement policy: 0 = BRRIP, 1 = FIFO
    uint8_t policy;
    // Per-way RRPV for BRRIP
    uint8_t rrpv[LLC_WAYS];
    // FIFO queue for each set
    uint8_t fifo_pos[LLC_WAYS];
    uint8_t fifo_head;
    // Adaptive stats
    uint32_t accesses, hits, misses, reused;
};

std::vector<SetState> sets(LLC_SETS);

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].policy = 0; // Start with BRRIP
        sets[s].accesses = sets[s].hits = sets[s].misses = sets[s].reused = 0;
        sets[s].fifo_head = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].rrpv[w] = LONG_RRPV;
            sets[s].fifo_pos[w] = w;
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
    } else { // FIFO
        // Find way with fifo_head position
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ss.fifo_pos[w] == ss.fifo_head)
                return w;
        }
        // Should not happen, fallback to way 0
        return 0;
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
    if (hit) {
        ss.hits++;
        ss.reused++;
    } else {
        ss.misses++;
    }

    // Policy adaptation every ADAPTIVE_WINDOW accesses
    if (ss.accesses % ADAPTIVE_WINDOW == 0) {
        double reuse_rate = (double)ss.reused / ss.accesses;
        double stream_rate = (double)ss.misses / ss.accesses;
        // If streaming (few reuses), prefer FIFO
        if (stream_rate > STREAM_THRESHOLD)
            ss.policy = 1; // FIFO
        else
            ss.policy = 0; // BRRIP
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

    // Update FIFO state
    if (ss.policy == 1) {
        // On fill, move head forward and set new block's position
        if (!hit) {
            ss.fifo_head = (ss.fifo_head + 1) % LLC_WAYS;
            ss.fifo_pos[way] = ss.fifo_head;
        }
        // On hit, do nothing (FIFO does not update on hit)
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t brrip_sets = 0, fifo_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (sets[s].policy == 0) brrip_sets++; else fifo_sets++;
    }
    std::cout << "BRRIP sets: " << brrip_sets << ", FIFO sets: " << fifo_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op or print similar info as PrintStats
}