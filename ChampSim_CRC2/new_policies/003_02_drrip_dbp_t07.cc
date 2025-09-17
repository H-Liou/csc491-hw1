#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRIP parameters
static const uint8_t MAX_RRPV   = 3;
static const uint8_t INIT_RRPV  = 2;

// DRRIP dueling parameters
static const uint32_t LEADER_SRRIP   = 32;   // # sets running fixed SRRIP
static const uint32_t LEADER_BRRIP   = 32;   // # sets running fixed BRRIP
static const uint32_t PSEL_BITS      = 10;
static const uint32_t PSEL_MAX       = (1 << PSEL_BITS) - 1;
static const uint32_t PSEL_THRESHOLD = (1 << (PSEL_BITS - 1));
static uint32_t       PSEL;                  // saturating DRRIP selector

// Bimodal RRIP (BRRIP) parameters
static const uint32_t BIP_TH        = 32;    // 1/32th of BRRIP inserts at INIT_RRPV
static uint32_t       BIP_counter;           // global counter for BRRIP

// Dead-block predictor: per-PC reuse prediction
static const uint32_t DBP_SIZE      = 1024;
static const uint32_t DBP_MASK      = (DBP_SIZE - 1);
static uint8_t        DBP[DBP_SIZE];         // 2-bit saturating counters

// Replacement metadata: RRPV per block
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Helper hash for PC or DBP index
static inline uint32_t PCHashAddr(uint64_t a, uint32_t mask) {
    return uint32_t((a ^ (a >> 12)) & mask);
}

void InitReplacementState() {
    // 1) Initialize RRPVs to "far away"
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // 2) Initialize DRRIP PSEL to neutral
    PSEL = PSEL_THRESHOLD;
    // 3) Reset BRRIP counter
    BIP_counter = 0;
    // 4) Clear dead-block predictor
    for (uint32_t i = 0; i < DBP_SIZE; i++) {
        DBP[i] = 0;
    }
}

uint32_t GetVictimInSet(
    uint32_t         cpu,
    uint32_t         set,
    const BLOCK     *current_set,
    uint64_t         PC,
    uint64_t         paddr,
    uint32_t         type
) {
    // Standard SRRIP victim selection: look for RRPV == MAX, else age all
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
    uint8_t  hit
) {
    // Compute a tiny DBP index from PC and block address
    uint32_t dbp_idx = uint32_t(((PC) ^ (paddr >> 6)) & DBP_MASK);

    if (hit) {
        // 1) On hit: strong promotion
        RRPV[set][way] = 0;
        // 2) Train DBP: record that this PC reused its block
        if (DBP[dbp_idx] < 3) {
            DBP[dbp_idx]++;
        }
        return;
    }

    // 3) On miss: first update PSEL in leader sets based on miss
    if (set < LEADER_SRRIP) {
        // SRRIP leader set missed → bias towards BRRIP
        if (PSEL < PSEL_MAX) {
            PSEL++;
        }
    } else if (set < (LEADER_SRRIP + LEADER_BRRIP)) {
        // BRRIP leader set missed → bias towards SRRIP
        if (PSEL > 0) {
            PSEL--;
        }
    }

    // 4) Choose insertion policy for this set
    bool use_srrip;
    if (set < LEADER_SRRIP) {
        use_srrip = true;
    } else if (set < (LEADER_SRRIP + LEADER_BRRIP)) {
        use_srrip = false;
    } else {
        // Follower sets consult PSEL MSB
        use_srrip = (PSEL < PSEL_THRESHOLD);
    }

    // 5) Dead-block check: if DBP == 0, treat as non-reused → bypass cache
    uint8_t new_rrpv;
    if (DBP[dbp_idx] == 0) {
        new_rrpv = MAX_RRPV;
    } else {
        if (use_srrip) {
            // SRRIP-style shallow insert
            new_rrpv = INIT_RRPV;
        } else {
            // BRRIP-style deep insert with 1/32 probability of INIT
            if ((BIP_counter++ & (BIP_TH - 1)) == 0) {
                new_rrpv = INIT_RRPV;
            } else {
                new_rrpv = MAX_RRPV;
            }
        }
    }

    // 6) Install new RRPV and reset DBP entry for this PC
    RRPV[set][way]    = new_rrpv;
    DBP[dbp_idx]      = 0;
}

void PrintStats() {
    // Optionally report PSEL and DBP saturation
}

void PrintStats_Heartbeat() {
    // no heartbeat stats
}