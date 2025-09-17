#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// PC‐based predictor parameters
static const uint32_t PC_TABLE_SIZE        = 2048;
static const uint8_t  PREDICTOR_MAX_CTR    = 3;
static const uint8_t  PREDICTION_THRESHOLD = 2;

// SRRIP parameters
static const uint8_t  MAX_RRPV = 3;

// Predictor table: one 2‐bit saturating counter per PC signature
struct PCEntry {
    uint8_t ctr;
} PCtable[PC_TABLE_SIZE];

// Per‐line RRPV values
static uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Statistics
static uint64_t total_accesses = 0;
static uint64_t total_hits     = 0;

// Initialize replacement state
void InitReplacementState() {
    // Initialize PC predictor counters to an intermediate value
    for (uint32_t i = 0; i < PC_TABLE_SIZE; i++) {
        PCtable[i].ctr = PREDICTION_THRESHOLD - 1;
    }
    // Initialize all lines’ RRPV to max (cold)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            rrpv[s][w] = MAX_RRPV;
        }
    }
}

// Find victim via SRRIP: look for RRPV==MAX_RRPV, otherwise age all and retry
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // SRRIP victim search
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (rrpv[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Age all lines by incrementing RRPV (capped at MAX_RRPV)
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (rrpv[set][w] < MAX_RRPV) {
                rrpv[set][w]++;
            }
        }
    }
}

// Update replacement state on hit or miss‐fill
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
    uint32_t pc_idx = PC & (PC_TABLE_SIZE - 1);
    PCEntry &entry = PCtable[pc_idx];

    if (hit) {
        // On hit: reset RRPV, strengthen predictor
        total_hits++;
        if (entry.ctr < PREDICTOR_MAX_CTR) {
            entry.ctr++;
        }
        rrpv[set][way] = 0;
    } else {
        // On miss‐fill: weaken predictor, choose insertion RRPV
        if (entry.ctr > 0) {
            entry.ctr--;
        }
        // If predictor thinks temporal, use near‐MRU; else use MAX_RRPV (fast eviction)
        uint8_t insert_rrpv = (entry.ctr >= PREDICTION_THRESHOLD) ? (MAX_RRPV - 1) : MAX_RRPV;
        rrpv[set][way] = insert_rrpv;
    }
}

// Print end‐of‐simulation statistics
void PrintStats() {
    double hit_rate = (total_accesses ? (double)total_hits / total_accesses : 0.0);
    std::cout << "PC-SRRIP-BP Total Accesses: " << total_accesses
              << " Hits: " << total_hits
              << " HitRate: " << (hit_rate * 100.0) << "%\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    double hit_rate = (total_accesses ? (double)total_hits / total_accesses : 0.0);
    std::cout << "[Heartbeat] Accesses=" << total_accesses
              << " Hits=" << total_hits
              << " HitRate=" << (hit_rate * 100.0) << "%\n";
}