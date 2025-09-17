#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE   1
#define LLC_SETS   (NUM_CORE * 2048)
#define LLC_WAYS   16

// RRPV parameters
static const uint8_t MAX_RRPV    = 3;

// SHiP-lite parameters
static const uint32_t SHIP_SIG_SIZE = 2048;
static const uint32_t SHIP_SIG_MASK = (SHIP_SIG_SIZE - 1);
static const uint8_t  SHIP_CTR_MAX   = 3;
static const uint8_t  SHIP_INIT_VAL  = 2;

// Replacement metadata
static uint8_t RRPV[LLC_SETS][LLC_WAYS];
static uint8_t SHIP_CTR[SHIP_SIG_SIZE];

// Simple hash of PC to a small signature
static inline uint32_t
Signature(uint64_t PC)
{
    // mix bits and mask
    return uint32_t((PC ^ (PC >> 4) ^ (PC >> 10)) & SHIP_SIG_MASK);
}

void InitReplacementState()
{
    // Initialize all lines to "far" RRPV so they are quickly replaceable
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Initialize SHiP counters to a weakly reusable value
    for (uint32_t i = 0; i < SHIP_SIG_SIZE; i++) {
        SHIP_CTR[i] = SHIP_INIT_VAL;
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
    // Standard SRRIP victim: scan for RRPV==MAX_RRPV, age otherwise
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // no line at MAX_RRPV? age everyone
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
    uint32_t way,        // way of the accessed or filled line
    uint64_t paddr,
    uint64_t PC,
    uint64_t victim_addr,
    uint32_t type,
    uint8_t hit
) {
    uint32_t sig = Signature(PC);
    if (hit) {
        // On hit, strongly promote and strengthen the predictor
        RRPV[set][way] = 0;
        if (SHIP_CTR[sig] < SHIP_CTR_MAX) {
            SHIP_CTR[sig]++;
        }
    } else {
        // On miss, weaken predictor and set insertion depth
        if (SHIP_CTR[sig] > 0) {
            SHIP_CTR[sig]--;
        }
        // If counter predicts reuse (>=2), insert as MRU, else as LRU
        if (SHIP_CTR[sig] >= 2) {
            RRPV[set][way] = 0;
        } else {
            RRPV[set][way] = MAX_RRPV;
        }
    }
}

void PrintStats() {
    // no extra stats
}

void PrintStats_Heartbeat() {
    // no extra stats
}