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
#define NUM_LEADER_SETS 32

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX 3

// Per-block metadata
std::vector<uint8_t> block_rrpv;      // [LLC_SETS * LLC_WAYS], 2 bits
std::vector<uint8_t> block_dead;      // [LLC_SETS * LLC_WAYS], 2 bits

// DRRIP set-dueling
std::vector<uint8_t> set_type;        // [LLC_SETS], 0: follower, 1: SRRIP leader, 2: BRRIP leader
uint16_t psel;                        // 10-bit PSEL counter

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t sr_insert = 0;
uint64_t br_insert = 0;
uint64_t dead_insert = 0;
uint64_t dead_evicted = 0;

// Helper: assign leader sets
void assign_leader_sets() {
    set_type.resize(LLC_SETS, 0);
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        set_type[i] = 1; // SRRIP leader
        set_type[LLC_SETS - 1 - i] = 2; // BRRIP leader
    }
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_dead.resize(LLC_SETS * LLC_WAYS, 0);
    assign_leader_sets();
    psel = PSEL_MAX / 2;
    access_counter = 0;
    hits = 0;
    sr_insert = 0;
    br_insert = 0;
    dead_insert = 0;
    dead_evicted = 0;
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
    // Standard RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] < RRPV_MAX)
            block_rrpv[idx]++;
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

    // --- Dead-block counter decay every 4096 accesses ---
    if ((access_counter & 0xFFF) == 0) {
        for (auto& db : block_dead)
            if (db > 0) db--;
    }

    // --- On hit: promote to MRU, reset dead counter ---
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        block_dead[idx] = 0;
        return;
    }

    // --- On eviction: increment dead counter for victim block ---
    if (block_rrpv[idx] == RRPV_MAX) {
        if (block_dead[idx] < DEAD_MAX) block_dead[idx]++;
        if (block_dead[idx] == DEAD_MAX) dead_evicted++;
    }

    // --- DRRIP insertion policy ---
    uint8_t ins_rrpv = RRPV_MAX; // default distant
    uint8_t stype = set_type[set];
    if (block_dead[idx] == DEAD_MAX) {
        // Dead block predicted: insert at distant RRPV
        ins_rrpv = RRPV_MAX;
        dead_insert++;
    } else {
        // Use DRRIP policy
        if (stype == 1) { // SRRIP leader
            ins_rrpv = 2; // SRRIP: insert at RRPV=2
            sr_insert++;
        } else if (stype == 2) { // BRRIP leader
            ins_rrpv = (rand() % 32 == 0) ? 2 : RRPV_MAX; // BRRIP: 1/32 at RRPV=2, else RRPV=3
            br_insert++;
        } else {
            // Follower: use PSEL to choose
            if (psel >= (PSEL_MAX / 2))
                ins_rrpv = 2; // SRRIP
            else
                ins_rrpv = (rand() % 32 == 0) ? 2 : RRPV_MAX; // BRRIP
        }
    }
    block_rrpv[idx] = ins_rrpv;

    // --- DRRIP set-dueling update ---
    // Only update PSEL for leader sets
    if (stype == 1) { // SRRIP leader
        if (hit && psel < PSEL_MAX) psel++;
    } else if (stype == 2) { // BRRIP leader
        if (hit && psel > 0) psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Detector Hybrid Policy\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "SRRIP inserts: " << sr_insert << "\n";
    std::cout << "BRRIP inserts: " << br_insert << "\n";
    std::cout << "Dead-block inserts: " << dead_insert << "\n";
    std::cout << "Dead-block evictions: " << dead_evicted << "\n";
    std::cout << "PSEL: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DRRIP+Dead heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", SRRIP=" << sr_insert
              << ", BRRIP=" << br_insert
              << ", Dead-insert=" << dead_insert
              << ", Dead-evict=" << dead_evicted
              << ", PSEL=" << psel << "\n";
}