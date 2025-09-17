#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define BRRIP_INSERT_PROB 32 // 1/32 probability for BRRIP
#define NUM_LEADER_SETS 32
#define PSEL_MAX 1023
#define PSEL_INIT (PSEL_MAX / 2)
#define DEAD_DECAY_PERIOD 100000 // Decay dead counters every N accesses

// Per-block metadata: 2-bit RRPV, 2-bit dead counter
std::vector<uint8_t> block_rrpv;
std::vector<uint8_t> block_dead;

// DRRIP set-dueling
std::vector<bool> is_srrip_leader;
std::vector<bool> is_brrip_leader;
uint16_t psel;

// Dead-block decay bookkeeping
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t dead_evictions = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, 3); // LRU
    block_dead.resize(LLC_SETS * LLC_WAYS, 2); // Neutral deadness
    is_srrip_leader.resize(LLC_SETS, false);
    is_brrip_leader.resize(LLC_SETS, false);
    psel = PSEL_INIT;

    // Assign leader sets evenly
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = true; // first N sets SRRIP leader
        is_brrip_leader[LLC_SETS - 1 - i] = true; // last N sets BRRIP leader
    }

    access_counter = 0;
    hits = 0;
    dead_evictions = 0;
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
    // Prefer blocks with dead_counter==0
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_dead[idx] == 0)
            return way;
    }

    // Standard RRIP: find block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == 3)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] < 3)
            block_rrpv[idx]++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == 3)
            return way;
    }
    // If still none, pick way 0
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

    // Decay dead counters periodically to avoid staleness
    if (access_counter % DEAD_DECAY_PERIOD == 0) {
        for (size_t i = 0; i < block_dead.size(); ++i) {
            if (block_dead[i] > 0)
                block_dead[i]--;
        }
    }

    size_t idx = get_block_idx(set, way);

    // On hit: promote block to MRU, increment dead counter
    if (hit) {
        block_rrpv[idx] = 0;
        hits++;
        if (block_dead[idx] < 3)
            block_dead[idx]++;
        return;
    }

    // DRRIP insertion policy selection
    bool use_srrip = false;
    if (is_srrip_leader[set])
        use_srrip = true;
    else if (is_brrip_leader[set])
        use_srrip = false;
    else
        use_srrip = (psel >= (PSEL_MAX / 2));

    uint8_t insert_rrpv = 2; // SRRIP default
    if (!use_srrip) {
        // BRRIP: Insert at RRPV=3 with low probability
        insert_rrpv = (rand() % BRRIP_INSERT_PROB == 0) ? 2 : 3;
    }

    block_rrpv[idx] = insert_rrpv;
    block_dead[idx] = 2; // neutral deadness on insertion

    // On eviction: update PSEL and dead counter
    if (victim_addr != 0) {
        // Determine which leader policy this set is (based on victim set)
        if (is_srrip_leader[set]) {
            // If victim reused before eviction, increment PSEL
            size_t victim_idx = get_block_idx(set, way);
            if (block_dead[victim_idx] > 0 && psel < PSEL_MAX)
                psel++;
        } else if (is_brrip_leader[set]) {
            // If victim reused before eviction, decrement PSEL
            size_t victim_idx = get_block_idx(set, way);
            if (block_dead[victim_idx] > 0 && psel > 0)
                psel--;
        }
        // Dead-block eviction bookkeeping
        size_t victim_idx = get_block_idx(set, way);
        if (block_dead[victim_idx] == 0)
            dead_evictions++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Detector Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Dead-block evictions: " << dead_evictions << "\n";
    std::cout << "PSEL value: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DRRIP+Dead heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", dead_evictions=" << dead_evictions
              << ", psel=" << psel << "\n";
}