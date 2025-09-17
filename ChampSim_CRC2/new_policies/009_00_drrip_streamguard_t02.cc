#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRIP parameters
static const uint8_t MAX_RRPV      = 3;
static const uint8_t SRRIP_RRPV    = (MAX_RRPV - 1);
static const uint32_t THIN_PROB    = 32;    // BRRIP thin insertion rate 1/32

// DRRIP set-dueling parameters
static const uint32_t DUELERS      = 64;    // 32 SRRIP + 32 BRRIP
static const uint32_t LEADER_QUOTA = 32;
static const uint16_t PSEL_MAX     = 1023;  // 10-bit
static const uint16_t PSEL_INIT    = PSEL_MAX / 2;
static uint16_t       PSEL;
static bool           isSRRIPLeader[LLC_SETS];
static bool           isBRRIPLeader[LLC_SETS];

// Per-PC reuse predictor (streaming guard), 2-bit saturating [0..3]
static const uint32_t SIG_BITS     = 10;
static const uint32_t SIG_SZ       = (1 << SIG_BITS);
static const uint8_t  SIG_MAX      = 3;
static const uint8_t  SIG_INIT     = 1;     // neutral reuse level
static uint8_t        PCReuse[SIG_SZ];

// Per-line RRPV
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Simple PC hashing
static inline uint32_t PCHash(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

// Initialize replacement state
void InitReplacementState() {
    // Initialize RRPVs
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Init reuse predictor
    for (uint32_t i = 0; i < SIG_SZ; i++) {
        PCReuse[i] = SIG_INIT;
    }
    // Init PSEL and leaders
    PSEL = PSEL_INIT;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        uint32_t slot = s & (DUELERS - 1);
        isSRRIPLeader[s] = (slot < LEADER_QUOTA);
        isBRRIPLeader[s] = (slot >= LEADER_QUOTA && slot < 2 * LEADER_QUOTA);
    }
}

// Victim selection: find way with RRPV == MAX_RRPV, else age all
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
        // Age all
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] < MAX_RRPV) {
                RRPV[set][w]++;
            }
        }
    }
}

// Update replacement state on hit/miss
void UpdateReplacementState(
    uint32_t cpu, uint32_t set, uint32_t way,
    uint64_t paddr, uint64_t PC, uint64_t victim_addr,
    uint32_t type, uint8_t hit
) {
    uint32_t sig = PCHash(PC, SIG_SZ - 1);

    // Update reuse predictor
    if (hit) {
        if (PCReuse[sig] < SIG_MAX) PCReuse[sig]++;
    } else {
        if (PCReuse[sig] > 0) PCReuse[sig]--;
    }

    if (hit) {
        // On hit: promote to MRU
        RRPV[set][way] = 0;
        return;
    }

    // Miss: update DRRIP PSEL in leader sets
    if (isSRRIPLeader[set]) {
        // SRRIP leader miss => punish SRRIP
        if (PSEL > 0) PSEL--;
    } else if (isBRRIPLeader[set]) {
        // BRRIP leader miss => punish BRRIP
        if (PSEL < PSEL_MAX) PSEL++;
    }

    // Decide policy for this set
    bool use_srrip;
    if (isSRRIPLeader[set]) {
        use_srrip = true;
    } else if (isBRRIPLeader[set]) {
        use_srrip = false;
    } else {
        use_srrip = (PSEL > (PSEL_MAX / 2));
    }

    // Streaming guard: if PC shows zero reuse, insert maximally cold
    if (PCReuse[sig] == 0) {
        RRPV[set][way] = MAX_RRPV;
        return;
    }

    // DRRIP insertion
    if (use_srrip) {
        // SRRIP: always insert at RRPV = MAX_RRPV - 1
        RRPV[set][way] = SRRIP_RRPV;
    } else {
        // BRRIP: insert at MAX_RRPV except 1/THIN_PROB chance to insert at SRRIP_RRPV
        uint32_t low5 = PCHash(PC, THIN_PROB - 1);
        if (low5 == 0) {
            RRPV[set][way] = SRRIP_RRPV;
        } else {
            RRPV[set][way] = MAX_RRPV;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // No custom stats
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No custom stats
}