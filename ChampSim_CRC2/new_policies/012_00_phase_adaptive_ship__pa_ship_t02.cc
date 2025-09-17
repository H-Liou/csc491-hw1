#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters
static const uint8_t  MAX_RRPV        = 3;  // 2-bit RRPV [0..3]
static const uint8_t  NEAR_MRU_RRPV   = 1;  // near-MRU insertion

// PC signature predictor
static const uint32_t SIG_BITS        = 12;
static const uint32_t SIG_TABLE_SZ    = (1 << SIG_BITS);
static const uint8_t  SIG_MAX         = 15; // 4-bit [0..15]
static uint8_t        SigTable[SIG_TABLE_SZ];

// Streaming detector per set
static uint64_t       LastAddr[LLC_SETS];
static uint64_t       LastDelta[LLC_SETS];
static uint8_t        StreamConf[LLC_SETS];

// RRIP RRPVs
static uint8_t        RRPV[LLC_SETS][LLC_WAYS];

// Simple PC hash
static inline uint32_t PCIndex(uint64_t PC) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & (SIG_TABLE_SZ - 1));
}

void InitReplacementState() {
    // Initialize RRPVs
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
        // Streaming detector
        LastAddr[s]   = 0;
        LastDelta[s]  = 0;
        StreamConf[s] = 0;
    }
    // Initialize signature table to weakly cold
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_MAX / 4; 
    }
}

// Find victim in the set by searching for RRPV == MAX_RRPV, aging others if needed
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
        // Age everyone
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
    uint32_t sig = PCIndex(PC);

    if (hit) {
        // On hit: promote to MRU and strengthen signature
        RRPV[set][way] = 0;
        if (SigTable[sig] < SIG_MAX) {
            SigTable[sig]++;
        }
        return;
    }

    // MISS --------------------------------------------------------
    // 1) Streaming detection: count identical deltas
    uint64_t delta = (LastAddr[set] ? paddr - LastAddr[set] : 0);
    if (delta != 0 && delta == LastDelta[set]) {
        StreamConf[set]++;
    } else {
        StreamConf[set] = 0;
    }
    LastDelta[set] = delta;
    LastAddr[set]  = paddr;
    bool is_stream = (StreamConf[set] >= 4);

    // 2) PC signature strength
    uint8_t strength = SigTable[sig]; // [0..15]

    // 3) Decide insertion RRPV
    if (is_stream) {
        // Bypass long streams
        RRPV[set][way] = MAX_RRPV;
    }
    else if (strength >= (SIG_MAX / 2)) {
        // Hot PC => MRU
        RRPV[set][way] = 0;
    }
    else if (strength >= (SIG_MAX / 4)) {
        // Moderate => near-MRU
        RRPV[set][way] = NEAR_MRU_RRPV;
    }
    else {
        // Cold => bypass
        RRPV[set][way] = MAX_RRPV;
    }

    // 4) On mis-predicted "hot" (i.e., we thought hot but it didn't hit), decay
    if (strength > (SIG_MAX / 2)) {
        // give negative feedback
        SigTable[sig] = (SigTable[sig] > 0) ? SigTable[sig] - 1 : 0;
    }
}

void PrintStats() {
    // No additional stats
}

void PrintStats_Heartbeat() {
    // No-op
}