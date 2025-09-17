#include <vector>
#include <cstdint>
#include <algorithm>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters
static const uint8_t  MAX_RRPV   = 3;             // 2-bit RRPV [0..3]
static const uint8_t  SRRIP_INS  = MAX_RRPV - 1;  // insert near-MRU

// SHiP-lite signature table
#define SIG_BITS       10
#define SIG_ENTRIES    (1 << SIG_BITS)
#define SIG_MASK       (SIG_ENTRIES - 1)
static uint8_t        SigCtr[SIG_ENTRIES];        // 2-bit saturating [0..3]

// Per-line RRPV
static uint8_t        RRPV[LLC_SETS][LLC_WAYS];

void InitReplacementState() {
    // Initialize RRPVs to long-life (LRU insertion) and SigCtr to weakly reusable
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    for (uint32_t i = 0; i < SIG_ENTRIES; i++) {
        SigCtr[i] = 1;  // start in middle (bias to LIP)
    }
}

// Find a victim by searching for RRPV == MAX_RRPV, aging otherwise
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK */*current_set*/,
    uint64_t /*PC*/,
    uint64_t /*paddr*/,
    uint32_t /*type*/
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
    // unreachable
    return 0;
}

// Update on hit or miss
void UpdateReplacementState(
    uint32_t /*cpu*/,
    uint32_t set,
    uint32_t way,
    uint64_t /*paddr*/,
    uint64_t PC,
    uint64_t /*victim_addr*/,
    uint32_t /*type*/,
    uint8_t hit
) {
    uint32_t sig = (PC >> 2) & SIG_MASK;
    if (hit) {
        // On hit, promote to MRU and strengthen PC's reuse counter
        RRPV[set][way] = 0;
        if (SigCtr[sig] < 3) {
            SigCtr[sig]++;
        }
    } else {
        // On miss, choose insertion depth based on PC signature
        uint8_t ctr = SigCtr[sig];
        uint8_t ins_rrpv = (ctr >= 2 ? SRRIP_INS : MAX_RRPV);
        RRPV[set][way] = ins_rrpv;
    }
}

void PrintStats() {
    // No additional stats
}

void PrintStats_Heartbeat() {
    // No-op
}