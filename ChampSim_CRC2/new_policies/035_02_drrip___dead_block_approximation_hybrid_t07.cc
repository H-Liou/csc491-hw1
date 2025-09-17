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

// Set-dueling parameters
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)

std::vector<uint8_t> block_rrpv; // 2 bits per block
std::vector<uint8_t> block_reuse; // 2 bits per block: dead-block counter

// DRRIP set-dueling
std::vector<uint8_t> set_type; // 0=SRRIP leader, 1=BRRIP leader, 2=follower
uint32_t psel; // 10 bits

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t dead_evicts = 0;
uint64_t decay_counter = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_reuse.resize(LLC_SETS * LLC_WAYS, 1); // start as not dead
    set_type.resize(LLC_SETS, 2); // default: follower
    psel = PSEL_MAX / 2;

    // Assign leader sets
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i) {
        set_type[i] = 0; // SRRIP leader
        set_type[LLC_SETS - 1 - i] = 1; // BRRIP leader
    }
    access_counter = 0;
    hits = 0;
    dead_evicts = 0;
    decay_counter = 0;
}

// Find victim: prefer dead blocks (reuse==0), else standard RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, try to find a block with reuse==0
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        size_t idx = get_block_idx(set, way);
        if (block_reuse[idx] == 0)
        {
            dead_evicts++;
            return way;
        }
    }
    // Standard RRIP victim selection: block with RRPV==RRPV_MAX
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] < RRPV_MAX)
            block_rrpv[idx]++;
    }
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Fallback: way 0
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

    // Dead-block: On hit, increment reuse (max 3), on fill, reset to 1
    if (hit) {
        hits++;
        block_rrpv[idx] = 0; // promote to MRU
        if (block_reuse[idx] < 3) block_reuse[idx]++;
    } else {
        // Determine insertion policy
        uint8_t policy;
        if (set_type[set] == 0) // SRRIP leader
            policy = 0;
        else if (set_type[set] == 1) // BRRIP leader
            policy = 1;
        else // follower
            policy = (psel >= (PSEL_MAX / 2)) ? 0 : 1;

        // SRRIP: insert at RRPV=2; BRRIP: insert at RRPV=3 (1/32 probability insert at 2)
        uint8_t ins_rrpv = 2;
        if (policy == 1) {
            if ((rand() % 32) == 0) ins_rrpv = 2;
            else ins_rrpv = 3;
        }
        block_rrpv[idx] = ins_rrpv;
        block_reuse[idx] = 1; // not dead, new line

        // Set-dueling: update PSEL if in leader set
        if (set_type[set] == 0) {
            if (hit && psel < PSEL_MAX) psel++;
        } else if (set_type[set] == 1) {
            if (hit && psel > 0) psel--;
        }
    }

    // Dead-block decay: every 8192 accesses, halve all block_reuse
    decay_counter++;
    if (decay_counter >= 8192) {
        for (size_t i = 0; i < block_reuse.size(); ++i) {
            block_reuse[i] >>= 1;
        }
        decay_counter = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-block Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Dead-block evictions: " << dead_evicts << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DRRIP+Dead heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", dead_evicts=" << dead_evicts << "\n";
}