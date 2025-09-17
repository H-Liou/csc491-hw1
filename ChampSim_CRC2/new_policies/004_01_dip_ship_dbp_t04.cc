#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE     1
#define LLC_SETS     (NUM_CORE * 2048)
#define LLC_WAYS     16

// RRIP parameters
static const uint8_t MAX_RRPV      = 3;    // 2-bit
static const uint8_t INIT_BIP_RRPV = MAX_RRPV - 1;

// DIP parameters
static const uint8_t PSEL_MAX      = 63;   // 6-bit counter
static const uint8_t PSEL_INIT     = 32;
static uint8_t       PSEL;                 // global selector

// SHiP-lite signature table
static const uint32_t SIG_SIZE      = 4096;
static const uint32_t SIG_MASK      = SIG_SIZE - 1;
static uint8_t        SHCT[SIG_SIZE];       // 2-bit saturating

// Dead-block predictor: 2-bit per line
static uint8_t DBcnt[LLC_SETS][LLC_WAYS];   // 0..3

// Replacement metadata: RRPV per block
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Simple PC hash
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 12)) & mask);
}

// Simple fill counter for BIP randomness
static uint32_t fill_counter = 0;

void InitReplacementState() {
    // Initialize RRPVs to MAX, DB counters and SHCT to zero, PSEL to midpoint
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w]   = MAX_RRPV;
            DBcnt[s][w]  = 0;
        }
    }
    for (uint32_t i = 0; i < SIG_SIZE; i++) {
        SHCT[i] = 0;
    }
    PSEL = PSEL_INIT;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find a way with RRPV==MAX, preferring DBcnt==0 (dead)
    while (true) {
        // First scan for RRPV==MAX and DBcnt==0
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV && DBcnt[set][w] == 0) {
                return w;
            }
        }
        // Then scan for any RRPV==MAX
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Otherwise age all
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
        // On hit: promote strongly, refresh dead-block counter, train SHCT
        RRPV[set][way]   = 0;
        DBcnt[set][way]  = 3;             // saturate
        if (SHCT[sig] < 3) SHCT[sig]++;
        return;
    }

    // On miss: decay all DB counters in this set
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (DBcnt[set][w] > 0) {
            DBcnt[set][w]--;
        }
    }

    // Determine if this set is a leader for BIP or LIP (64-set dueling)
    bool is_bip_leader = ((set & 63) < 32);
    bool is_lip_leader = ((set & 63) >= 32 && (set & 63) < 64);
    bool use_bip;
    if (is_bip_leader) {
        use_bip = true;
        if (PSEL < PSEL_MAX) PSEL++;     // prefer BIP on miss
    } else if (is_lip_leader) {
        use_bip = false;
        if (PSEL > 0)      PSEL--;       // prefer LIP on miss
    } else {
        // Follower: choose by PSEL
        use_bip = (PSEL >= (PSEL_MAX >> 1));
    }

    // Compute insertion RRPV
    uint8_t new_rrpv;
    // SHiP override: strong reuse PCs get immediate promote on refill
    if (SHCT[sig] >= 2) {
        new_rrpv = 0;
    } else {
        if (use_bip) {
            // Bimodal: mostly cold, occasionally near-cold
            fill_counter++;
            if ((fill_counter & 31) == 0) {
                new_rrpv = INIT_BIP_RRPV;
            } else {
                new_rrpv = MAX_RRPV;
            }
        } else {
            // LIP: insert at far RRPV
            new_rrpv = MAX_RRPV;
        }
    }

    // Install new line metadata
    RRPV[set][way]  = new_rrpv;
    DBcnt[set][way] = 0;  // start as potentially live; will decay
}

void PrintStats() {
    // no additional statistics
}

void PrintStats_Heartbeat() {
    // no heartbeat stats
}