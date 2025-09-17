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

// SHiP‐lite signature table (2‐bit counters)
static const uint32_t SIG_SIZE  = 2048;
static const uint32_t SIG_MASK  = (SIG_SIZE - 1);
static uint8_t        SHCT[SIG_SIZE];

// Dead‐block predictor (2‐bit per‐line)
static uint8_t DBcounter[LLC_SETS][LLC_WAYS];

// DRRIP set‐dueling
static const uint32_t DUEL_LEADER_SETS = 64;
static bool         is_leader_sr[LLC_SETS];
static bool         is_leader_br[LLC_SETS];
static uint16_t     PSEL;               // 10‐bit saturating

// Bimodal Insertion Policy counter for BRRIP
static uint32_t     BIP_counter;

// Replacement metadata
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Simple PC→index hash
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 12)) & mask);
}

void InitReplacementState() {
    // Initialize RRPVs to max
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w]       = MAX_RRPV;
            DBcounter[s][w]  = 0;
        }
    }
    // Reset SHiP counters
    for (uint32_t i = 0; i < SIG_SIZE; i++) {
        SHCT[i] = 0;
    }
    // Initialize DRRIP dueling sets
    PSEL = (1 << 9); // middle of 10‐bit counter (0..1023)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        is_leader_sr[s] = (s < DUEL_LEADER_SETS/2);
        is_leader_br[s] = (s >= DUEL_LEADER_SETS/2 && s < DUEL_LEADER_SETS);
    }
    // Reset BIP counter
    BIP_counter = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // SRRIP‐style victim selection
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
        // On hit: promote and train predictors
        RRPV[set][way] = 0;
        // Train SHiP
        if (SHCT[sig] < 3) SHCT[sig]++;
        // Train dead‐block predictor
        if (DBcounter[set][way] < 3) DBcounter[set][way]++;
        return;
    }

    // On miss: choose insertion RRPV
    uint8_t new_rrpv;
    // 1) Dead‐block bypass
    if (DBcounter[set][way] == 0) {
        // predicted dead → bypass nearly entirely
        new_rrpv = MAX_RRPV;
    } else {
        // 2) SHiP‐driven hot insertion
        if (SHCT[sig] >= 2) {
            new_rrpv = INIT_RRPV;
        } else {
            // 3) DRRIP‐dueling for cold PCs
            bool use_srrip;
            if (is_leader_sr[set]) {
                use_srrip = true;
            } else if (is_leader_br[set]) {
                use_srrip = false;
            } else {
                use_srrip = (PSEL >= (1 << 9));
            }
            if (use_srrip) {
                new_rrpv = INIT_RRPV;
            } else {
                // BRRIP = BIP strategy
                if ((BIP_counter++ & 31) == 0) {
                    new_rrpv = INIT_RRPV;
                } else {
                    new_rrpv = MAX_RRPV;
                }
            }
        }
    }

    RRPV[set][way] = new_rrpv;

    // Optionally update PSEL in leader sets based on replacement outcome
    // (not shown: could track reuse on filled lines to drive PSEL)
}

void PrintStats() {
    // no end‐of‐run stats
}

void PrintStats_Heartbeat() {
    // no heartbeat stats
}