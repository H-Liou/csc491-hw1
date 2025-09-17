#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// PC‐based SHiP predictor parameters
static const uint32_t PC_TABLE_SIZE        = 4096;
static const uint8_t  PREDICTOR_MAX_CTR    = 7;
static const uint8_t  PREDICTION_THRESHOLD = 4;

// SRRIP parameters
static const uint8_t  MAX_RRPV = 3;

// Dueling parameters
static const uint32_t DUELING_SETS    = 64;       // number of sampled sets
static const uint32_t LEADER_HALF     = 32;       // half for SRRIP, half for SHiP
static const uint64_t DUELING_EPOCH   = (1 << 20); // 1M accesses between policy updates
static const uint32_t MIN_SAMPLE      = 100;      // minimum samples before comparing

// Predictor table: one 3‐bit saturating counter per PC signature
struct PCEntry {
    uint8_t ctr;
} PCtable[PC_TABLE_SIZE];

// Per‐line RRPV values
static uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Global statistics
static uint64_t total_accesses = 0;
static uint64_t total_hits     = 0;

// Dueling statistics
static uint64_t duel_accesses     = 0;
static uint64_t sr_hits           = 0;
static uint64_t sr_accesses       = 0;
static uint64_t pc_hits           = 0;
static uint64_t pc_accesses       = 0;
static uint8_t  policy_mode       = 0; // 0=>SRRIP, 1=>SHiP

// Helpers to identify leader sets
static inline bool is_sr_leader(uint32_t set) {
    uint32_t idx = set & (DUELING_SETS - 1);
    return idx < LEADER_HALF;
}
static inline bool is_pc_leader(uint32_t set) {
    uint32_t idx = set & (DUELING_SETS - 1);
    return (idx >= LEADER_HALF) && (idx < DUELING_SETS);
}

// Initialize replacement state
void InitReplacementState() {
    // Initialize PC‐predictor to weakly taken (favor SHiP initially)
    for (uint32_t i = 0; i < PC_TABLE_SIZE; i++) {
        PCtable[i].ctr = PREDICTION_THRESHOLD;
    }
    // Initialize RRPV to coldest
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            rrpv[s][w] = MAX_RRPV;
        }
    }
    // Reset stats
    total_accesses = total_hits = 0;
    duel_accesses = sr_hits = sr_accesses = pc_hits = pc_accesses = 0;
    policy_mode = 0;
}

// SRRIP victim search (common to both policies)
static uint32_t SRRIP_Victim(uint32_t set) {
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (rrpv[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Age all
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (rrpv[set][w] < MAX_RRPV) {
                rrpv[set][w]++;
            }
        }
    }
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
    // Always use the RRPV victim search
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
    duel_accesses++;

    bool sr_lead = is_sr_leader(set);
    bool pc_lead = is_pc_leader(set);
    bool use_pc  = sr_lead ? false
                   : pc_lead ? true
                   : (policy_mode == 1);

    // Update dueling stats for leader sets
    if (sr_lead) {
        sr_accesses++;
        if (hit) sr_hits++;
    } else if (pc_lead) {
        pc_accesses++;
        if (hit) pc_hits++;
    }

    // On hit: both policies reset to MRU
    if (hit) {
        total_hits++;
        rrpv[set][way] = 0;
        // If using SHiP, strengthen predictor
        if (use_pc) {
            uint32_t idx = PC & (PC_TABLE_SIZE - 1);
            if (PCtable[idx].ctr < PREDICTOR_MAX_CTR) {
                PCtable[idx].ctr++;
            }
        }
    }
    else {
        // Miss – choose insertion RRPV
        uint8_t insert_rrpv;
        if (!use_pc) {
            // SRRIP: near-MRU
            insert_rrpv = MAX_RRPV - 1;
        } else {
            // SHiP: PC-based
            uint32_t idx = PC & (PC_TABLE_SIZE - 1);
            uint8_t ctr = PCtable[idx].ctr;
            // Weaken predictor
            if (ctr > 0) PCtable[idx].ctr--;
            // If predicted likely to reuse, near-MRU; else far
            insert_rrpv = (ctr >= PREDICTION_THRESHOLD) ? (MAX_RRPV - 1) : MAX_RRPV;
        }
        rrpv[set][way] = insert_rrpv;
    }

    // Periodically decide winner of dueling
    if ((duel_accesses & (DUELING_EPOCH - 1)) == 0) {
        // Only compare if we have enough samples
        if (sr_accesses >= MIN_SAMPLE && pc_accesses >= MIN_SAMPLE) {
            double sr_rate = double(sr_hits) / double(sr_accesses);
            double pc_rate = double(pc_hits) / double(pc_accesses);
            policy_mode = (pc_rate > sr_rate) ? 1 : 0;
        }
        // Reset dueling counters
        sr_hits = sr_accesses = pc_hits = pc_accesses = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    double hit_rate = total_accesses ? (double)total_hits / total_accesses : 0.0;
    std::cout << "DRRIP_SHiP Total Accesses: " << total_accesses
              << " Hits: " << total_hits
              << " HitRate: " << (hit_rate * 100.0) << "%\n";
    std::cout << "Final mode: " << (policy_mode ? "SHiP" : "SRRIP") << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    double hit_rate = total_accesses ? (double)total_hits / total_accesses : 0.0;
    std::cout << "[Heartbeat] Accesses=" << total_accesses
              << " Hits=" << total_hits
              << " HitRate=" << (hit_rate * 100.0) << "%\n";
    std::cout << "[Heartbeat] Mode=" << (policy_mode ? "SHiP" : "SRRIP") << "\n";
}