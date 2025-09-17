#include <vector>
#include <cstdint>
#include <algorithm>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRIP parameters
static const uint8_t MAX_RRPV       = 3;    // 2-bit [0..3]
static const uint8_t SRRIP_INS      = MAX_RRPV - 1; // =2

// SHiP parameters
static const uint32_t SHCT_SIZE     = 64;   // 6-bit index
// 2-bit saturating counters [0..3]
static uint8_t SHCT[SHCT_SIZE];

// Per-line metadata
static uint8_t RRPV[LLC_SETS][LLC_WAYS];    // 2-bit RRPV per line
static uint8_t SigIdx[LLC_SETS][LLC_WAYS];  // 6-bit SHCT index per line
static uint8_t HitFlag[LLC_SETS][LLC_WAYS]; // 1 if line saw a hit since insertion

void InitReplacementState() {
    // Initialize all RRPVs to max (victim candidates),
    // clear per-line flags, and init SHCT to weakly-not-reuse (1).
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w]    = MAX_RRPV;
            SigIdx[s][w]  = 0;
            HitFlag[s][w] = 0;
        }
    }
    for (uint32_t i = 0; i < SHCT_SIZE; i++) {
        SHCT[i] = 1; // weakly no-reuse
    }
}

// Find a victim by standard RRIP: look for RRPV==MAX, else age
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
        // age all lines
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
    if (hit) {
        // On hit: promote to MRU
        RRPV[set][way] = 0;
        // Train SHCT
        uint8_t idx = SigIdx[set][way];
        if (SHCT[idx] < 3) {
            SHCT[idx]++;
        }
        HitFlag[set][way] = 1;
        return;
    }
    // MISS path --------------------------------------------------
    // 1) Train on the evicted block if it never hit
    uint8_t old_idx = SigIdx[set][way];
    if (!HitFlag[set][way]) {
        if (SHCT[old_idx] > 0) {
            SHCT[old_idx]--;
        }
    }
    // 2) Compute new signature index: low bits of PC ^ paddr
    uint8_t new_idx = ((PC ^ (paddr >> 6)) & (SHCT_SIZE - 1));
    SigIdx[set][way]  = new_idx;
    HitFlag[set][way] = 0;

    // 3) Choose insertion RRPV based on SHCT counter
    uint8_t c = SHCT[new_idx];
    uint8_t ins_rrpv;
    if (c >= 2) {
        // high reuse ⇒ MRU
        ins_rrpv = 0;
    } else if (c == 1) {
        // moderate ⇒ SRRIP near‐MRU
        ins_rrpv = SRRIP_INS;
    } else {
        // no reuse ⇒ bypass
        ins_rrpv = MAX_RRPV;
    }
    RRPV[set][way] = ins_rrpv;
}

void PrintStats() {
    // no additional stats
}

void PrintStats_Heartbeat() {
    // no-op
}