#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRPV constants
static const uint8_t MAX_RRPV = 3;
static const uint8_t SHCT_MAX = 3;
static const uint32_t SHCT_SIZE = 256; // 2-bit predictor entries

// Replacement state
static uint8_t RRPV[LLC_SETS][LLC_WAYS];
static bool   reuse_flag[LLC_SETS][LLC_WAYS];

// Signature predictor table (2-bit saturating)
static uint8_t SHCT[SHCT_SIZE];

// Hash victim_addr to predictor index
static inline uint32_t SigIndex(uint64_t addr) {
    // drop block offset bits, xor upper and lower
    uint64_t x = (addr >> 6) ^ (addr >> 16);
    return (uint32_t)(x & (SHCT_SIZE - 1));
}

void InitReplacementState() {
    // Initialize RRPVs to max (cold)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
            reuse_flag[s][w] = false;
        }
    }
    // Initialize signature counters to weakly not-reuse (1)
    for (uint32_t i = 0; i < SHCT_SIZE; i++) {
        SHCT[i] = 1;
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find a line with RRPV == MAX_RRPV
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Increment RRPV of all lines (aging)
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] < MAX_RRPV) {
                RRPV[set][w]++;
            }
        }
    }
}

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
    // Case: HIT in this line
    if (hit) {
        // Promote to MRU
        RRPV[set][way] = 0;
        reuse_flag[set][way] = true;
        return;
    }
    // MISS: a victim was evicted (victim_addr)
    if (victim_addr != (uint64_t)(-1)) {
        // Update SHCT based on victim reuse
        uint32_t idx = SigIndex(victim_addr);
        if (reuse_flag[set][way]) {
            if (SHCT[idx] < SHCT_MAX) SHCT[idx]++;
        } else {
            if (SHCT[idx] > 0) SHCT[idx]--;
        }
    }
    // Insert the new line at (set,way) with RRPV based on predictor
    uint32_t idx_new = SigIndex(paddr);
    uint8_t ctr = SHCT[idx_new];
    // Strong reuse predictor => insert at RRPV=MAX-1; else RRPV=MAX
    RRPV[set][way] = (ctr >= 2 ? MAX_RRPV - 1 : MAX_RRPV);
    reuse_flag[set][way] = false;
}

void PrintStats() {
    // Nothing special
}

void PrintStats_Heartbeat() {
    // Nothing special
}