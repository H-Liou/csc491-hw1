#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE   1
#define LLC_SETS   (NUM_CORE * 2048)
#define LLC_WAYS   16

// RRPV parameters for SRRIP
static const uint8_t MAX_RRPV      = 3;  // 2-bit RRPV [0..3]
static const uint8_t NEAR_MRU_RRPV = MAX_RRPV - 1;

// Dead‐block predictor: 4K entries, 1 byte each
static const uint32_t DP_BITS = 12;
static const uint32_t DP_SIZE = (1 << DP_BITS);
static uint8_t      DeadPred[DP_SIZE];

// RRPV array per cache line
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Simple hash from paddr to dead table index
static inline uint32_t DeadIndex(uint64_t paddr) {
    return uint32_t((paddr >> 6) & (DP_SIZE - 1));
}

void InitReplacementState() {
    // Initialize all RRPVs to MAX (most likely to be replaced)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Clear dead predictor
    for (uint32_t i = 0; i < DP_SIZE; i++) {
        DeadPred[i] = 0;
    }
}

// Find a victim by searching for RRPV == MAX_RRPV, aging on the fly
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Age all lines
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] < MAX_RRPV) {
                RRPV[set][w]++;
            }
        }
    }
}

// Update on hit or miss
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
    if (hit) {
        // On a hit: promote block to MRU and clear dead‐bit
        RRPV[set][way] = 0;
        uint32_t idx = DeadIndex(paddr);
        DeadPred[idx] = 0;
        return;
    }

    // MISS path -------------------------------------------------
    // 1) Mark the just‐evicted block region as dead
    if (victim_addr) {
        uint32_t vidx = DeadIndex(victim_addr);
        DeadPred[vidx] = 1;
    }

    // 2) Insert the new block
    uint32_t idx = DeadIndex(paddr);
    if (DeadPred[idx]) {
        // Bypass predicted dead lines
        RRPV[set][way] = MAX_RRPV;
    } else {
        // Standard SRRIP insertion (near MRU)
        RRPV[set][way] = NEAR_MRU_RRPV;
    }
}

void PrintStats() {
    // No additional stats
}

void PrintStats_Heartbeat() {
    // No-op
}