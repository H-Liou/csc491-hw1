#include <vector>
#include <cstdint>
#include <algorithm>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE          1
#define LLC_SETS          (NUM_CORE * 2048)
#define LLC_WAYS          16

// RRIP parameters
static const uint8_t MAX_RRPV      = 3;    // 2-bit [0..3]
static const uint8_t SRRIP_INS     = MAX_RRPV - 1; // =2
static const uint8_t LIP_INS       = 1;    // shallow insertion for mildly reused

// SHiP-style signature table
static const uint32_t SIG_TABLE_SIZE = 4096;
static const uint32_t SIG_TABLE_MASK = SIG_TABLE_SIZE - 1;
static uint8_t      SigCtr[SIG_TABLE_SIZE];  // 2-bit [0..3]

// Per-line RRPV
static uint8_t      RRPV[LLC_SETS][LLC_WAYS];

void InitReplacementState() {
    // Initialize all RRPVs to MAX (all lines cold)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Initialize SHiP signature counters to weakly cold (1)
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; i++) {
        SigCtr[i] = 1;
    }
}

// Find a victim by classic RRIP: look for RRPV==MAX, else age all
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
        // age every line
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
    // Compute PC signature index
    uint32_t sig_idx = (PC >> 4) & SIG_TABLE_MASK;

    if (hit) {
        // Promote to MRU
        RRPV[set][way] = 0;
        // Strengthen the PC predictor
        if (SigCtr[sig_idx] < 3) {
            SigCtr[sig_idx]++;
        }
    } else {
        // MISS path ---------------------------------------------------
        // We weaken the PC predictor on misses
        if (SigCtr[sig_idx] > 0) {
            SigCtr[sig_idx]--;
        }
        // Choose insertion RRPV based on predictor state
        uint8_t ctr = SigCtr[sig_idx];
        uint8_t ins_rrpv;
        if (ctr == 0) {
            // Predicted dead block → bypass
            ins_rrpv = MAX_RRPV;
        } else if (ctr == 1) {
            // Mild reuse → shallow insertion
            ins_rrpv = LIP_INS;
        } else if (ctr == 2) {
            // Regular reuse → SRRIP insertion
            ins_rrpv = SRRIP_INS;
        } else {
            // Hot block → MRU insertion
            ins_rrpv = 0;
        }
        RRPV[set][way] = ins_rrpv;
    }
}

void PrintStats() {
    // nothing extra
}

void PrintStats_Heartbeat() {
    // no periodic stats
}