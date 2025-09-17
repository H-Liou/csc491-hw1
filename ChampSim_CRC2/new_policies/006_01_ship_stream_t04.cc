#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRPV parameters
static const uint8_t MAX_RRPV       = 3;
static const uint8_t SRRIP_RRPV     = (MAX_RRPV - 1);

// SHiP-lite signature table (12-bit PC sig → 2-bit counter)
static const uint32_t SIG_BITS      = 12;
static const uint32_t SIG_TABLE_SZ  = (1 << SIG_BITS);
static const uint32_t SIG_MASK      = (SIG_TABLE_SZ - 1);
static const uint8_t  SIG_MAX       = 3;    // 2-bit counter max
static const uint8_t  SIG_INIT      = 1;    // start slightly cold
static const uint8_t  HOT_THRES     = 3;    // only top count is "hot"
static uint8_t        SigTable[SIG_TABLE_SZ];

// Per-block RRPVs
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Streaming detection state
static uint64_t LastAddr[NUM_CORE];
static int64_t  LastDelta[NUM_CORE];

// Simple hash of PC to index tables
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    // Initialize all RRPVs to "long" (MAX)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Initialize SHiP signature counters
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_INIT;
    }
    // Init streaming state
    for (uint32_t c = 0; c < NUM_CORE; c++) {
        LastAddr[c]  = 0;
        LastDelta[c] = 0;
    }
}

// SRRIP victim selection (evict any line with RRPV == MAX_RRPV)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP scan & age
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
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
    uint32_t sig = PCIndex(PC, SIG_MASK);

    if (hit) {
        // On hit: strong promotion + train signature
        RRPV[set][way] = 0;
        if (SigTable[sig] < SIG_MAX) {
            SigTable[sig]++;
        }
        return;
    }

    // MISS: detect simple streaming (repeat delta) per core
    int64_t delta = int64_t(paddr) - int64_t(LastAddr[cpu]);
    bool streaming = (LastDelta[cpu] != 0 && delta == LastDelta[cpu]);
    LastDelta[cpu] = delta;
    LastAddr[cpu]  = paddr;

    // Insert decision
    uint8_t new_rrpv;
    if (streaming) {
        // Bypass streaming: fill at RRPV=MAX so evicted soon
        new_rrpv = MAX_RRPV;
    }
    else if (SigTable[sig] >= HOT_THRES) {
        // PC is hot: prioritize retention
        new_rrpv = 0;
    }
    else {
        // PC is cold/unknown: long RRPV
        new_rrpv = MAX_RRPV;
    }

    RRPV[set][way] = new_rrpv;
}

void PrintStats() {
    // no extra stats
}

void PrintStats_Heartbeat() {
    // no heartbeat stats
}