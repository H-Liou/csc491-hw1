#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3

#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define NUM_LEADER_SETS 64
#define SRRIP_LEADER_OFFSET 0
#define BRRIP_LEADER_OFFSET NUM_LEADER_SETS

// Dead-block counter parameters
#define DEAD_BITS 2
#define DEAD_MAX 3

// Per-block metadata
std::vector<uint8_t> block_rrpv;   // 2 bits per block
std::vector<uint8_t> block_dead;   // 2 bits per block

// DRRIP set-dueling
std::vector<uint8_t> set_type;     // 0: follower, 1: SRRIP leader, 2: BRRIP leader
uint16_t psel;                     // 10-bit policy selector

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t dead_evictions = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_dead.resize(LLC_SETS * LLC_WAYS, 0);
    set_type.resize(LLC_SETS, 0);
    psel = PSEL_MAX / 2; // neutral

    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        set_type[(SRRIP_LEADER_OFFSET + i) % LLC_SETS] = 1; // SRRIP leader
        set_type[(BRRIP_LEADER_OFFSET + i) % LLC_SETS] = 2; // BRRIP leader
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
    // Prefer blocks with dead-block counter == DEAD_MAX
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_dead[idx] == DEAD_MAX)
            return way;
    }
    // Otherwise, standard RRIP: find block with RRPV==RRPV_MAX
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] < RRPV_MAX)
            block_rrpv[idx]++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Fallback: pick way 0
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
    size_t idx = get_block_idx(set, way);

    // On hit: promote to MRU, reset dead-block counter
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        block_dead[idx] = 0;
        return;
    }

    // On fill: choose insertion depth
    uint8_t ins_rrpv = RRPV_MAX; // default: LRU
    uint8_t setmode = set_type[set];
    bool is_srrip = false, is_brrip = false;

    if (setmode == 1) is_srrip = true;      // SRRIP leader
    else if (setmode == 2) is_brrip = true; // BRRIP leader
    else is_srrip = (psel >= (PSEL_MAX / 2)); // followers pick by psel

    if (is_srrip)
        ins_rrpv = 2; // SRRIP: insert at RRPV=2
    else
        ins_rrpv = (rand() % 32 == 0) ? 2 : RRPV_MAX; // BRRIP: insert at RRPV=2 with 1/32 probability

    block_rrpv[idx] = ins_rrpv;

    // Dead-block counter: increment on fill, saturate
    if (block_dead[idx] < DEAD_MAX)
        block_dead[idx]++;

    // On eviction: update PSEL for leader sets
    if (victim_addr != 0) {
        uint8_t victim_setmode = set_type[set];
        if (victim_setmode == 1) {
            // SRRIP leader: increment PSEL if hit
            if (hit && psel < PSEL_MAX) psel++;
        } else if (victim_setmode == 2) {
            // BRRIP leader: decrement PSEL if hit
            if (hit && psel > 0) psel--;
        }
        // Dead-block: count eviction if dead
        size_t victim_idx = get_block_idx(set, way);
        if (block_dead[victim_idx] == DEAD_MAX)
            dead_evictions++;
        // Reset dead-block counter on eviction
        block_dead[victim_idx] = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Approx Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Dead-block evictions: " << dead_evictions << "\n";
    std::cout << "PSEL: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DRRIP+Dead heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", dead_evictions=" << dead_evictions
              << ", PSEL=" << psel << "\n";
}