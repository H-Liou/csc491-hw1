#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRPV parameters
static const uint8_t MAX_RRPV = 3;        // 2-bit RRPV: 0..3

// DRRIP parameters
static const uint32_t SAMPLE_INTERVAL      = 64;   // one SRRIP set and one BRRIP set every 64 sets
static const uint32_t SRRIP_SAMPLE_OFFSET  = 0;
static const uint32_t BRRIP_SAMPLE_OFFSET  = 1;
static const uint16_t PSEL_BITS            = 10;
static const uint16_t PSEL_MAX             = (1 << PSEL_BITS) - 1;  // 1023
static const uint16_t PSEL_INIT            = PSEL_MAX / 2;          // 511
static const uint16_t PSEL_THRESHOLD       = PSEL_INIT;
static const uint32_t BIP_RATE            = 32;  // 1-in-32 chance to insert near-MRU in BRRIP
static uint64_t fill_count = 0;                    // for BIP pseudo-randomness

// Replacement state
static uint8_t  rrpv[LLC_SETS][LLC_WAYS];
static uint16_t PSEL;                 // policy selection counter
static uint64_t total_accesses = 0;
static uint64_t total_hits     = 0;

// Helpers
static inline bool is_srrip_sample(uint32_t set) {
    return ((set % SAMPLE_INTERVAL) == SRRIP_SAMPLE_OFFSET);
}
static inline bool is_brip_sample(uint32_t set) {
    return ((set % SAMPLE_INTERVAL) == BRRIP_SAMPLE_OFFSET);
}

// SRRIP victim search
static uint32_t SRRIP_Victim(uint32_t set) {
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (rrpv[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // age all if no MAX_RRPV found
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (rrpv[set][w] < MAX_RRPV) {
                rrpv[set][w]++;
            }
        }
    }
}

// Initialize replacement state
void InitReplacementState() {
    // Initialize RRPVs to coldest
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            rrpv[s][w] = MAX_RRPV;
        }
    }
    // Initialize PSEL to midpoint
    PSEL = PSEL_INIT;
    total_accesses = 0;
    total_hits     = 0;
    fill_count     = 0;
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Use SRRIP-style search for a victim
    return SRRIP_Victim(set);
}

// Update replacement state on hit or miss-fill
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
    total_accesses++;
    if (hit) {
        // On hit: promote to MRU (RRPV=0)
        total_hits++;
        rrpv[set][way] = 0;
        // Update PSEL if in a sample set
        if (is_srrip_sample(set)) {
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (is_brip_sample(set)) {
            if (PSEL > 0) PSEL--;
        }
    } else {
        // On miss: insertion policy
        bool use_srrip;
        if (is_srrip_sample(set)) {
            use_srrip = true;
        } else if (is_brip_sample(set)) {
            use_srrip = false;
        } else {
            // follower set: choose based on PSEL
            use_srrip = (PSEL >= PSEL_THRESHOLD);
        }
        if (use_srrip) {
            // SRRIP: near-MRU insertion
            rrpv[set][way] = MAX_RRPV - 1;
        } else {
            // Bimodal insertion: mostly cold, occasionally near-MRU
            fill_count++;
            if ((fill_count & (BIP_RATE - 1)) == 0) {
                rrpv[set][way] = MAX_RRPV - 1;
            } else {
                rrpv[set][way] = MAX_RRPV;
            }
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    double hit_rate = total_accesses ? (double)total_hits / total_accesses : 0.0;
    std::cout << "DRRIP Total Accesses: " << total_accesses
              << " Hits: " << total_hits
              << " HitRate: " << (hit_rate * 100.0) << "%\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    double hit_rate = total_accesses ? (double)total_hits / total_accesses : 0.0;
    std::cout << "[Heartbeat][DRRIP] Accesses=" << total_accesses
              << " Hits=" << total_hits
              << " HitRate=" << (hit_rate * 100.0) << "%\n";
}