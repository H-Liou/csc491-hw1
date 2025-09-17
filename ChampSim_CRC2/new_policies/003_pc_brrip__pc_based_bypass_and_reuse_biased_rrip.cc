#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRPV parameters
static const uint8_t  MAX_RRPV          = 3;   // 2-bit RRPV: 0..3

// PC‐based predictor parameters
static const uint32_t PC_TABLE_SIZE     = 4096;
static const uint8_t  PC_INIT_CTR       = 8;   // start at mid strength
static const uint8_t  PC_MAX_CTR        = 15;  // 4-bit counter
static const uint8_t  PC_BYPASS_TH      = 2;   // <=2 => bypass‐like
static const uint8_t  PC_MEDIUM_TH      = 6;   // <=6 => medium reuse

// Predictor table: one 4-bit saturating counter per PC signature
struct PCEntry {
    uint8_t ctr;
};
static PCEntry PCtable[PC_TABLE_SIZE];

// Per‐line RRPV values
static uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Global statistics
static uint64_t total_accesses = 0;
static uint64_t total_hits     = 0;

// Helper: SRRIP victim search
static uint32_t SRRIP_Victim(uint32_t set) {
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (rrpv[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Age all if no MAX_RRPV found
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (rrpv[set][w] < MAX_RRPV) {
                rrpv[set][w]++;
            }
        }
    }
}

// Initialize replacement state
void InitReplacementState() {
    // Initialize PC predictor to mid‐strength
    for (uint32_t i = 0; i < PC_TABLE_SIZE; i++) {
        PCtable[i].ctr = PC_INIT_CTR;
    }
    // Initialize all RRPVs to coldest
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            rrpv[s][w] = MAX_RRPV;
        }
    }
    // Reset stats
    total_accesses = 0;
    total_hits     = 0;
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
    // Use SRRIP-style victim selection
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
    uint32_t idx = (uint32_t)(PC & (PC_TABLE_SIZE - 1));
    if (hit) {
        // On hit: strong retention
        total_hits++;
        rrpv[set][way] = 0;
        // Strengthen predictor
        if (PCtable[idx].ctr < PC_MAX_CTR) {
            PCtable[idx].ctr++;
        }
    } else {
        // On miss: weaken predictor
        if (PCtable[idx].ctr > 0) {
            PCtable[idx].ctr--;
        }
        // Choose insertion RRPV based on predictor
        uint8_t ctr = PCtable[idx].ctr;
        if (ctr <= PC_BYPASS_TH) {
            // Low-confidence: bypass-like (cold)
            rrpv[set][way] = MAX_RRPV;
        }
        else if (ctr <= PC_MEDIUM_TH) {
            // Medium confidence: near-MRU
            rrpv[set][way] = MAX_RRPV - 1;
        }
        else {
            // High-confidence: MRU
            rrpv[set][way] = 0;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    double hit_rate = total_accesses ? (double)total_hits / total_accesses : 0.0;
    std::cout << "PC-BRRIP Total Accesses: " << total_accesses
              << " Hits: " << total_hits
              << " HitRate: " << (hit_rate * 100.0) << "%\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    double hit_rate = total_accesses ? (double)total_hits / total_accesses : 0.0;
    std::cout << "[Heartbeat][PC-BRRIP] Accesses=" << total_accesses
              << " Hits=" << total_hits
              << " HitRate=" << (hit_rate * 100.0) << "%\n";
}