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
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define BRRIP_INSERT_PROB 32 // 1/32 probability for BRRIP
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)

// Dead-block approximation
#define REUSE_BITS 2
#define REUSE_MAX ((1 << REUSE_BITS) - 1)
#define DECAY_INTERVAL 100000

// Per-block metadata
std::vector<uint8_t> block_rrpv;   // 2 bits per block
std::vector<uint8_t> block_reuse;  // 2 bits per block

// DRRIP set-dueling
std::vector<uint8_t> is_leader_srrip; // per set: 1 if SRRIP leader, 0 if BRRIP leader, else follower
uint32_t psel = PSEL_MAX / 2; // 10-bit PSEL, start neutral

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
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX); // LRU
    block_reuse.resize(LLC_SETS * LLC_WAYS, 0);

    is_leader_srrip.resize(LLC_SETS, 0);
    // Assign leader sets: first half SRRIP, second half BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_srrip[i] = 1; // SRRIP leader
        is_leader_srrip[LLC_SETS - 1 - i] = 2; // BRRIP leader
    }
    access_counter = 0;
    hits = 0;
    dead_evictions = 0;
    psel = PSEL_MAX / 2;
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
    // Prefer blocks with reuse counter == 0 (dead-block approx)
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX && block_reuse[idx] == 0)
            return way;
    }
    // Otherwise, standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            size_t idx = get_block_idx(set, way);
            if (block_rrpv[idx] == RRPV_MAX)
                return way;
        }
        // Increment RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            size_t idx = get_block_idx(set, way);
            if (block_rrpv[idx] < RRPV_MAX)
                block_rrpv[idx]++;
        }
    }
    return 0; // fallback
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

    // Periodic decay of reuse counters
    if (access_counter % DECAY_INTERVAL == 0) {
        for (size_t i = 0; i < block_reuse.size(); ++i) {
            if (block_reuse[i] > 0)
                block_reuse[i]--;
        }
    }

    // On hit: promote to MRU, increment reuse counter
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        if (block_reuse[idx] < REUSE_MAX)
            block_reuse[idx]++;
        return;
    }

    // On fill: choose insertion depth
    uint8_t leader_type = 0;
    if (set < NUM_LEADER_SETS)
        leader_type = 1; // SRRIP leader
    else if (set >= LLC_SETS - NUM_LEADER_SETS)
        leader_type = 2; // BRRIP leader

    bool use_srrip = false;
    if (leader_type == 1)
        use_srrip = true;
    else if (leader_type == 2)
        use_srrip = false;
    else
        use_srrip = (psel >= (PSEL_MAX / 2));

    // SRRIP: insert at RRPV=2
    // BRRIP: insert at RRPV=3 with low probability, else RRPV=2
    uint8_t insert_rrpv = 2;
    if (!use_srrip) {
        // BRRIP: 1/32 probability insert at RRPV=3
        if ((rand() % BRRIP_INSERT_PROB) == 0)
            insert_rrpv = 3;
    }
    block_rrpv[idx] = insert_rrpv;
    block_reuse[idx] = 0; // reset reuse counter

    // On eviction: update PSEL if leader set
    if (victim_addr != 0) {
        size_t victim_idx = get_block_idx(set, way);
        uint8_t victim_leader = 0;
        if (set < NUM_LEADER_SETS)
            victim_leader = 1;
        else if (set >= LLC_SETS - NUM_LEADER_SETS)
            victim_leader = 2;

        // If victim block was reused, reward policy
        if (victim_leader == 1) { // SRRIP leader
            if (block_reuse[victim_idx] > 0 && psel < PSEL_MAX)
                psel++;
            else if (block_reuse[victim_idx] == 0 && psel > 0)
                psel--;
        } else if (victim_leader == 2) { // BRRIP leader
            if (block_reuse[victim_idx] > 0 && psel > 0)
                psel--;
            else if (block_reuse[victim_idx] == 0 && psel < PSEL_MAX)
                psel++;
        }
        // Dead-block eviction stat
        if (block_reuse[victim_idx] == 0)
            dead_evictions++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Approximation Hybrid\n";
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