#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
static const uint8_t MAX_RRPV  = 3;  // 2-bit field: 0..3
static const uint8_t INIT_RRPV = 2;  // SRRIP default

// SHiP-lite PC signature table
static const uint32_t SIG_SIZE = 1024;
static const uint32_t SIG_MASK = (SIG_SIZE - 1);
static uint8_t SHCT[SIG_SIZE];      // 2-bit saturating counters [0..3]

// Replacement metadata
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Simple hash: PC -> signature
static inline uint32_t Signature(uint64_t PC) {
    return uint32_t((PC ^ (PC >> 12) ^ (PC >> 20)) & SIG_MASK);
}

void InitReplacementState() {
    // Initialize RRPVs to MAX (likely to be chosen for eviction)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Initialize PC signature counters to weakly reusable (2)
    for (uint32_t i = 0; i < SIG_SIZE; i++) {
        SHCT[i] = 2;
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
    // Standard SRRIP victim selection
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
    uint32_t sig = Signature(PC);
    if (hit) {
        // On hit: strong promotion & reward the PC
        RRPV[set][way] = 0;
        if (SHCT[sig] < 3) {
            SHCT[sig]++;
        }
    } else {
        // On miss: use SHCT to pick insertion depth
        bool predicted_reuse = (SHCT[sig] >= 2);
        uint8_t new_rrpv = predicted_reuse ? INIT_RRPV : MAX_RRPV;
        // Penalize the PC for a miss insertion
        if (SHCT[sig] > 0) {
            SHCT[sig]--;
        }
        RRPV[set][way] = new_rrpv;
    }
}

void PrintStats() {
    // Nothing to print
}

void PrintStats_Heartbeat() {
    // Nothing to print
}