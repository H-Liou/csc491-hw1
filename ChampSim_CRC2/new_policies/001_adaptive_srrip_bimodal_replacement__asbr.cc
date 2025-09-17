#include <vector>
#include <cstdint>
#include <iostream>
#include <random>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP constants
#define RRPV_BITS 2
#define MAX_RRPV ((1 << RRPV_BITS) - 1)
#define INSERT_RRPV_LONG MAX_RRPV
#define INSERT_RRPV_SHORT (MAX_RRPV - 1)
#define PROMOTE_RRPV 0

// Bimodal bypassing constants
#define BYPASS_PROB 8 // 1 out of 8 inserts are bypassed in "bad" sets
#define BAD_SET_THRESHOLD 8 // If last 32 accesses had <=8 hits, consider set "bad"
#define SET_HISTORY_LEN 32

struct SetHistory {
    uint8_t hits;
    uint8_t ptr;
    uint8_t history[SET_HISTORY_LEN]; // 1: hit, 0: miss
    SetHistory() : hits(0), ptr(0) {
        for (int i = 0; i < SET_HISTORY_LEN; ++i) history[i] = 0;
    }
    void update(uint8_t hit) {
        hits -= history[ptr];
        history[ptr] = hit;
        hits += hit;
        ptr = (ptr + 1) % SET_HISTORY_LEN;
    }
    bool is_bad() const { return hits <= BAD_SET_THRESHOLD; }
};

struct SRRIPRepl {
    uint8_t rrpv[LLC_SETS][LLC_WAYS];
    SetHistory set_history[LLC_SETS];
    std::mt19937 rng;
    std::uniform_int_distribution<int> dist;

    SRRIPRepl() : rng(42), dist(0, BYPASS_PROB-1) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                rrpv[s][w] = MAX_RRPV;
    }
};

SRRIPRepl repl;

// Initialize replacement state
void InitReplacementState() {
    repl = SRRIPRepl();
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
    // SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (repl.rrpv[set][way] == MAX_RRPV)
                return way;
        }
        // Increment all RRPVs if no candidate found
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (repl.rrpv[set][way] < MAX_RRPV)
                repl.rrpv[set][way]++;
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
    // Update set history for bimodal bypass
    repl.set_history[set].update(hit);

    if (hit) {
        // On hit, promote block for reuse
        repl.rrpv[set][way] = PROMOTE_RRPV;
        return;
    }

    // On miss, decide insertion RRPV
    bool bypass = false;
    if (repl.set_history[set].is_bad()) {
        // In "bad" sets, bypass with probability
        if (repl.dist(repl.rng) == 0)
            bypass = true;
    }

    if (bypass) {
        // Bypass: don't insert, leave victim RRPV at MAX_RRPV
        repl.rrpv[set][way] = MAX_RRPV;
    } else {
        // Normal SRRIP insertion
        // Use short re-reference for instructions, long for data
        if (type == 0) // instruction
            repl.rrpv[set][way] = INSERT_RRPV_SHORT;
        else
            repl.rrpv[set][way] = INSERT_RRPV_LONG;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Optionally print SRRIP and bypass stats
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print stats
}