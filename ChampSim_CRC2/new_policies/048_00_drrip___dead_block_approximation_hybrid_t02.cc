#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3
#define BRRIP_INSERT_RRPV 2
#define SRRIP_INSERT_RRPV 1

#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)

// Dead-block approximation
#define REUSE_BITS 2
#define REUSE_MAX 3
#define DECAY_INTERVAL 4096 // Decay reuse counters every 4096 accesses

// Per-block metadata
std::vector<uint8_t> block_rrpv;      // [LLC_SETS * LLC_WAYS]
std::vector<uint8_t> block_reuse;     // [LLC_SETS * LLC_WAYS]

// DRRIP set-dueling
std::vector<uint8_t> is_leader_srrip; // [LLC_SETS]
std::vector<uint8_t> is_leader_brrip; // [LLC_SETS]
uint16_t psel = PSEL_MAX / 2;

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t dead_victim_evictions = 0;
uint64_t srrip_inserts = 0;
uint64_t brrip_inserts = 0;
uint64_t decay_events = 0;

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_reuse.resize(LLC_SETS * LLC_WAYS, 0);

    is_leader_srrip.resize(LLC_SETS, 0);
    is_leader_brrip.resize(LLC_SETS, 0);

    // Assign leader sets for SRRIP and BRRIP (evenly distributed)
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        is_leader_srrip[i] = 1; // First 64 sets are SRRIP leaders
        is_leader_brrip[LLC_SETS - 1 - i] = 1; // Last 64 sets are BRRIP leaders
    }

    psel = PSEL_MAX / 2;

    access_counter = 0;
    hits = 0;
    dead_victim_evictions = 0;
    srrip_inserts = 0;
    brrip_inserts = 0;
    decay_events = 0;
}

// Find victim in the set (prefer dead blocks)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, look for a block with reuse == 0 and RRPV == RRPV_MAX
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] == RRPV_MAX && block_reuse[idx] == 0) {
            dead_victim_evictions++;
            return way;
        }
    }
    // Next, look for any block with RRPV == RRPV_MAX
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] < RRPV_MAX) block_rrpv[idx]++;
    }
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Fallback
    return 0;
}

// Update replacement state
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
    access_counter++;
    size_t idx = set * LLC_WAYS + way;

    // --- Dead-block reuse counter update ---
    if (hit) {
        hits++;
        block_rrpv[idx] = 0; // Promote to MRU
        if (block_reuse[idx] < REUSE_MAX) block_reuse[idx]++;
        return;
    }

    // On miss, reset reuse counter
    block_reuse[idx] = 0;

    // --- DRRIP insertion policy ---
    uint8_t insert_rrpv;
    bool leader_srrip = is_leader_srrip[set];
    bool leader_brrip = is_leader_brrip[set];

    if (leader_srrip) {
        insert_rrpv = SRRIP_INSERT_RRPV;
        srrip_inserts++;
    } else if (leader_brrip) {
        insert_rrpv = BRRIP_INSERT_RRPV;
        brrip_inserts++;
    } else {
        // Use PSEL to choose
        if (psel >= (PSEL_MAX / 2)) {
            insert_rrpv = SRRIP_INSERT_RRPV;
            srrip_inserts++;
        } else {
            insert_rrpv = BRRIP_INSERT_RRPV;
            brrip_inserts++;
        }
    }
    block_rrpv[idx] = insert_rrpv;

    // --- DRRIP set-dueling feedback ---
    if (leader_srrip && hit) {
        if (psel < PSEL_MAX) psel++;
    }
    if (leader_brrip && hit) {
        if (psel > 0) psel--;
    }

    // --- Periodic decay of reuse counters ---
    if ((access_counter % DECAY_INTERVAL) == 0) {
        for (size_t i = 0; i < block_reuse.size(); i++) {
            if (block_reuse[i] > 0) block_reuse[i]--;
        }
        decay_events++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Approximation Hybrid Policy\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Dead-block victim evictions: " << dead_victim_evictions << "\n";
    std::cout << "SRRIP inserts: " << srrip_inserts << "\n";
    std::cout << "BRRIP inserts: " << brrip_inserts << "\n";
    std::cout << "Decay events: " << decay_events << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DRRIP+DeadBlock heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", dead_victims=" << dead_victim_evictions
              << ", SRRIP=" << srrip_inserts
              << ", BRRIP=" << brrip_inserts
              << ", decay=" << decay_events << "\n";
}