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
#define BRRIP_INSERT_PROB 32 // 1/32 probability for BRRIP long insertion

// Set-dueling parameters
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)

// Dead-block predictor
#define DEADCTR_BITS 2
#define DEADCTR_MAX 3
#define DEADCTR_DECAY_INTERVAL 8192 // Decay every N accesses

// Metadata
std::vector<uint8_t> block_rrpv;           // Per-block RRPV
std::vector<uint8_t> block_deadctr;        // Per-block dead-block counter (2 bits)
std::vector<uint8_t> set_type;             // Per-set: 0=Follower, 1=SRRIP Leader, 2=BRRIP Leader
uint32_t psel = PSEL_MAX / 2;              // DRRIP selector
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t dead_evictions = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Assign leader sets for set-dueling
void assign_leader_sets() {
    set_type.resize(LLC_SETS, 0);
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        set_type[i] = 1; // SRRIP leader
        set_type[LLC_SETS - 1 - i] = 2; // BRRIP leader
    }
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_deadctr.resize(LLC_SETS * LLC_WAYS, 0);
    assign_leader_sets();
    psel = PSEL_MAX / 2;
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
    // 1. Prefer blocks predicted dead (deadctr == DEADCTR_MAX)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        size_t idx = get_block_idx(set, way);
        if (block_deadctr[idx] == DEADCTR_MAX)
            return way;
    }
    // 2. Standard RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // 3. Increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] < RRPV_MAX)
            block_rrpv[idx]++;
    }
    // 4. Second pass
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        size_t idx = get_block_idx(set, way);
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

    // Periodic deadctr decay
    if ((access_counter & (DEADCTR_DECAY_INTERVAL - 1)) == 0) {
        for (size_t i = 0; i < block_deadctr.size(); ++i) {
            if (block_deadctr[i] > 0)
                block_deadctr[i]--;
        }
    }

    size_t idx = get_block_idx(set, way);

    // On hit: promote to MRU, reset deadctr
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        block_deadctr[idx] = 0;
        return;
    }

    // On fill: choose insertion policy
    uint8_t ins_rrpv = RRPV_MAX; // default: long RRIP
    uint8_t setrole = set_type[set];
    if (setrole == 1) { // SRRIP leader
        ins_rrpv = 1;
    } else if (setrole == 2) { // BRRIP leader
        ins_rrpv = (rand() % BRRIP_INSERT_PROB == 0) ? 1 : RRPV_MAX;
    } else { // Follower
        ins_rrpv = (psel >= (PSEL_MAX / 2)) ?
            ((rand() % BRRIP_INSERT_PROB == 0) ? 1 : RRPV_MAX) : 1;
    }
    block_rrpv[idx] = ins_rrpv;
    block_deadctr[idx] = 0;

    // On eviction: train DRRIP and deadctr
    if (victim_addr != 0) {
        size_t victim_idx = get_block_idx(set, way);
        // If victim was reused before eviction, reward policy
        if (block_rrpv[victim_idx] == 0) {
            if (setrole == 1 && psel < PSEL_MAX) psel++;
            else if (setrole == 2 && psel > 0) psel--;
            block_deadctr[victim_idx] = 0;
        } else {
            // If not reused, punish policy and increment deadctr
            if (setrole == 1 && psel > 0) psel--;
            else if (setrole == 2 && psel < PSEL_MAX) psel++;
            if (block_deadctr[victim_idx] < DEADCTR_MAX)
                block_deadctr[victim_idx]++;
            if (block_deadctr[victim_idx] == DEADCTR_MAX)
                dead_evictions++;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Prediction Hybrid Policy\n";
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
              << ", PSEL=" << psel << "\n";
}