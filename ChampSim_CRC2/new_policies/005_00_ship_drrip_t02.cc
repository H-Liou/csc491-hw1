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

// DRRIP set-dueling parameters
static const uint16_t PSEL_BITS     = 10;
static const uint16_t PSEL_MAX      = ((1 << PSEL_BITS) - 1);
static const uint16_t PSEL_INIT     = (PSEL_MAX >> 1);
static uint16_t       PSEL;

// SHiP-lite signature table
static const uint32_t SIG_BITS      = 12;
static const uint32_t SIG_TABLE_SZ  = (1 << SIG_BITS);
static const uint32_t SIG_MASK      = (SIG_TABLE_SZ - 1);
static const uint8_t  SIG_MAX       = 7;    // 3-bit counter max
static const uint8_t  SIG_INIT      = 4;    // start neutral
static const uint8_t  HOT_THRES     = 5;    // >=5 deemed hot
static uint8_t        SigTable[SIG_TABLE_SZ];

// Per-block RRPVs
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Simple hash of PC to index tables
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    PSEL = PSEL_INIT;
    // Initialize RRPVs to long (MAX_RRPV)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Initialize signature counters to neutral
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_INIT;
    }
}

// SRRIP victim selection (evict any line with RRPV==MAX_RRPV)
uint32_t GetVictimInSet(
    uint32_t cpu, uint32_t set,
    const BLOCK *current_set,
    uint64_t PC, uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Age everyone by one if no candidate
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
    // Compute PC signature
    uint32_t sig = PCIndex(PC, SIG_MASK);
    // Leader-set IDs for DRRIP (64-way sampling)
    bool is_srrip_leader = ((set & 63) == 0);
    bool is_brrip_leader = ((set & 63) == 1);

    if (hit) {
        // On hit: strong promotion
        RRPV[set][way] = 0;
        // Train SHiP signature
        if (SigTable[sig] < SIG_MAX) {
            SigTable[sig]++;
        }
        // Update DRRIP PSEL by leader sets
        if (is_srrip_leader) {
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (is_brrip_leader) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // MISS: decide insertion RRPV
    uint8_t new_rrpv;
    uint8_t sc = SigTable[sig];
    if (sc >= HOT_THRES) {
        // SHiP predicts hot: front priority
        new_rrpv = 0;
    } else if (sc == 0) {
        // SHiP predicts cold: long RRPV
        new_rrpv = MAX_RRPV;
    } else if (is_srrip_leader) {
        // SRRIP leader set: always MAX-1
        new_rrpv = SRRIP_RRPV;
    } else if (is_brrip_leader) {
        // BRRIP leader set: always MAX
        new_rrpv = MAX_RRPV;
    } else {
        // DRRIP chooses by PSEL
        if (PSEL > (PSEL_MAX >> 1)) {
            new_rrpv = SRRIP_RRPV;
        } else {
            // Bimodal RRIP: mostly MAX, occasionally MAX-1
            static uint32_t brip_ctr = 0;
            if ((brip_ctr++ & 63) == 0) {
                new_rrpv = SRRIP_RRPV;
            } else {
                new_rrpv = MAX_RRPV;
            }
        }
    }
    RRPV[set][way] = new_rrpv;
}

void PrintStats() {
    // no extra stats
}

void PrintStats_Heartbeat() {
    // no heartbeat stats
}