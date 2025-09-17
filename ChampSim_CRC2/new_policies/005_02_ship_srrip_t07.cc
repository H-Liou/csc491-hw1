#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE    1
#define LLC_SETS    (NUM_CORE * 2048)
#define LLC_WAYS    16

// RRPV parameters
static const uint8_t MAX_RRPV  = 3;
static const uint8_t INIT_RRPV = 2;  // SRRIP default insertion

// SHiP table (PC signature → 2-bit counter)
static const uint32_t SHIP_SIZE = 256;
static const uint32_t SHIP_MASK = (SHIP_SIZE - 1);
static uint8_t        SHIP[SHIP_SIZE];

// Per-line metadata
static uint8_t RRPV[LLC_SETS][LLC_WAYS];
static uint8_t Sig [LLC_SETS][LLC_WAYS]; // 8-bit PC signature
static uint8_t Used[LLC_SETS][LLC_WAYS]; // reuse flag: 1 if block was hit

// Simple hash: mix PC bits to index the SHIP table
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    // Initialize all RRPVs to long (cold / bypass)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
            Sig [s][w] = 0;
            Used[s][w] = 0;
        }
    }
    // Clear SHiP counters
    for (uint32_t i = 0; i < SHIP_SIZE; i++) {
        SHIP[i] = 0;
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu, uint32_t set,
    const BLOCK *current_set,
    uint64_t PC, uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection: age until some RRPV==MAX
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
    uint32_t cpu, uint32_t set, uint32_t way,
    uint64_t paddr, uint64_t PC, uint64_t victim_addr,
    uint32_t type, uint8_t hit
) {
    if (hit) {
        // On hit: strong promotion, mark reused
        RRPV[set][way] = 0;
        Used[set][way] = 1;
        return;
    }
    // On miss: first update SHiP on the evicted line
    uint8_t old_sig = Sig[set][way];
    uint8_t old_used = Used[set][way];
    if (old_used) {
        if (SHIP[old_sig] < 3) SHIP[old_sig]++;
    } else {
        if (SHIP[old_sig] > 0) SHIP[old_sig]--;
    }
    // Now install new block: compute signature from PC
    uint32_t sidx = PCIndex(PC, SHIP_MASK);
    Sig [set][way] = (uint8_t)sidx;
    Used[set][way] = 0;
    // Choose insertion RRPV based on SHiP counter
    uint8_t ctr = SHIP[sidx];
    uint8_t new_rrpv;
    if (ctr >= 2) {
        new_rrpv = 0;             // high reuse → front
    } else if (ctr == 1) {
        new_rrpv = INIT_RRPV;     // medium reuse
    } else {
        new_rrpv = MAX_RRPV;      // no reuse → bypass
    }
    RRPV[set][way] = new_rrpv;
}

void PrintStats() {
    // no extra stats
}

void PrintStats_Heartbeat() {
    // no heartbeat stats
}