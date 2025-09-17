#include <vector>
#include <cstdint>
#include <iostream>
#include <random>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)

// Per-block metadata: 2-bit RRPV, 2-bit reuse counter
std::vector<uint8_t> block_rrpv;
std::vector<uint8_t> block_reuse;

// DIP leader set tracking
std::vector<uint8_t> is_lip_leader;
std::vector<uint8_t> is_bip_leader;

// DIP PSEL counter
uint32_t psel;

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t lip_inserts = 0;
uint64_t bip_inserts = 0;
uint64_t deadblock_mru_promotes = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: periodic decay (every 4096 accesses)
void decay_reuse_counters() {
    if (access_counter % 4096 == 0) {
        for (size_t i = 0; i < block_reuse.size(); i++) {
            if (block_reuse[i] > 0)
                block_reuse[i]--;
        }
    }
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, 3); // LRU
    block_reuse.resize(LLC_SETS * LLC_WAYS, 0);

    is_lip_leader.resize(LLC_SETS, 0);
    is_bip_leader.resize(LLC_SETS, 0);

    // Randomly select 64 leader sets for LIP and 64 for BIP, non-overlapping
    std::vector<uint32_t> all_sets(LLC_SETS);
    for (uint32_t i = 0; i < LLC_SETS; i++) all_sets[i] = i;
    std::shuffle(all_sets.begin(), all_sets.end(), std::mt19937(42));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        is_lip_leader[all_sets[i]] = 1;
        is_bip_leader[all_sets[i + NUM_LEADER_SETS]] = 1;
    }

    psel = PSEL_INIT;

    access_counter = 0;
    hits = 0;
    lip_inserts = 0;
    bip_inserts = 0;
    deadblock_mru_promotes = 0;
}

// Victim selection: standard RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==3
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
    decay_reuse_counters();

    size_t idx = get_block_idx(set, way);

    // On hit: promote block to MRU if reuse counter is high
    if (hit) {
        hits++;
        if (block_reuse[idx] < 3)
            block_reuse[idx]++;
        if (block_reuse[idx] >= 2) {
            block_rrpv[idx] = 0; // MRU
            deadblock_mru_promotes++;
        }
        return;
    }

    // DIP insertion policy selection
    bool use_lip = false;
    bool use_bip = false;
    if (is_lip_leader[set]) use_lip = true;
    else if (is_bip_leader[set]) use_bip = true;
    else use_lip = (psel < (PSEL_MAX / 2));

    // LIP: always insert at LRU (RRPV=3)
    // BIP: insert at LRU (RRPV=3), but every 32nd insertion at MRU (RRPV=0)
    if (use_lip) {
        block_rrpv[idx] = 3;
        lip_inserts++;
    } else if (use_bip) {
        static uint32_t bip_count = 0;
        bip_count++;
        if ((bip_count & 0x1F) == 0) {
            block_rrpv[idx] = 0;
        } else {
            block_rrpv[idx] = 3;
        }
        bip_inserts++;
    } else {
        // Policy selection for follower sets
        if (psel < (PSEL_MAX / 2)) {
            block_rrpv[idx] = 3;
            lip_inserts++;
        } else {
            static uint32_t bip_count = 0;
            bip_count++;
            if ((bip_count & 0x1F) == 0) {
                block_rrpv[idx] = 0;
            } else {
                block_rrpv[idx] = 3;
            }
            bip_inserts++;
        }
    }
    block_reuse[idx] = 0; // reset reuse counter on insertion

    // On eviction from leader sets, update PSEL
    if (victim_addr != 0) {
        if (is_lip_leader[set]) {
            // If victim was reused (reuse counter >= 2), decrement PSEL
            size_t victim_idx = get_block_idx(set, way);
            if (block_reuse[victim_idx] >= 2 && psel > 0)
                psel--;
        } else if (is_bip_leader[set]) {
            // If victim was reused, increment PSEL
            size_t victim_idx = get_block_idx(set, way);
            if (block_reuse[victim_idx] >= 2 && psel < PSEL_MAX)
                psel++;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DIP-LIP/BIP + Dead-Block Approximation Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "LIP inserts: " << lip_inserts << "\n";
    std::cout << "BIP inserts: " << bip_inserts << "\n";
    std::cout << "Dead-block MRU promotes: " << deadblock_mru_promotes << "\n";
    std::cout << "PSEL: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DIP+DeadBlock heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", lip_inserts=" << lip_inserts
              << ", bip_inserts=" << bip_inserts
              << ", deadblock_mru=" << deadblock_mru_promotes
              << ", psel=" << psel << "\n";
}