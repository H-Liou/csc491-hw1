#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3

// DRRIP set-dueling parameters
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)

// Dead-block counter parameters
#define DEAD_BITS 2
#define DEAD_MAX 3
#define DECAY_INTERVAL 4096 // Decay every N accesses

// Per-block metadata
std::vector<uint8_t> block_rrpv;         // [LLC_SETS * LLC_WAYS]
std::vector<uint8_t> block_dead;         // [LLC_SETS * LLC_WAYS]

// DRRIP global state
uint16_t psel = PSEL_MAX / 2; // Start neutral

// Leader set bitmap: first half for SRRIP, second half for BRRIP
std::vector<uint8_t> is_leader_set; // [LLC_SETS]

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t dead_evictions = 0;
uint64_t decay_events = 0;
uint64_t srrip_inserts = 0;
uint64_t brrip_inserts = 0;

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_dead.resize(LLC_SETS * LLC_WAYS, 0);

    is_leader_set.resize(LLC_SETS, 0);
    // Mark NUM_LEADER_SETS/2 sets for SRRIP, NUM_LEADER_SETS/2 for BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS/2; i++) is_leader_set[i] = 1; // SRRIP leader
    for (uint32_t i = NUM_LEADER_SETS/2; i < NUM_LEADER_SETS; i++) is_leader_set[i] = 2; // BRRIP leader

    access_counter = 0;
    hits = 0;
    dead_evictions = 0;
    decay_events = 0;
    srrip_inserts = 0;
    brrip_inserts = 0;
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
    // Dead-block priority: evict dead blocks first
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_dead[idx] == DEAD_MAX)
            return way;
    }
    // RRIP victim selection
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

    // Decay dead-block counters periodically (global sweep)
    if (access_counter % DECAY_INTERVAL == 0) {
        for (size_t i = 0; i < block_dead.size(); i++) {
            if (block_dead[i] > 0) block_dead[i]--;
        }
        decay_events++;
    }

    // --- On hit: Promote to MRU, reset dead-block counter ---
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        block_dead[idx] = 0;
        return;
    }

    // --- On miss: Increment dead-block counter if not saturated ---
    if (block_dead[idx] < DEAD_MAX) block_dead[idx]++;

    // --- DRRIP insertion policy ---
    bool is_srrip_leader = (set < NUM_LEADER_SETS/2);
    bool is_brrip_leader = (set >= NUM_LEADER_SETS/2 && set < NUM_LEADER_SETS);

    uint8_t insert_rrpv = RRPV_MAX; // default is "long" insertion

    if (is_srrip_leader) {
        insert_rrpv = 2; // SRRIP: insert at RRPV=2
        srrip_inserts++;
    } else if (is_brrip_leader) {
        // BRRIP: insert at RRPV=2 with low probability, else RRPV=3
        if ((access_counter & 0x1F) == 0) insert_rrpv = 2;
        else insert_rrpv = 3;
        brrip_inserts++;
    } else {
        // Follower sets use PSEL to choose insertion policy
        if (psel >= (PSEL_MAX/2)) {
            // SRRIP
            insert_rrpv = 2;
            srrip_inserts++;
        } else {
            // BRRIP
            if ((access_counter & 0x1F) == 0) insert_rrpv = 2;
            else insert_rrpv = 3;
            brrip_inserts++;
        }
    }
    block_rrpv[idx] = insert_rrpv;

    // --- PSEL update: leader sets affect global policy ---
    if (is_srrip_leader && hit) {
        if (psel < PSEL_MAX) psel++;
    } else if (is_brrip_leader && hit) {
        if (psel > 0) psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Counter Hybrid Policy\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Dead block evictions: " << dead_evictions << "\n";
    std::cout << "Decay events: " << decay_events << "\n";
    std::cout << "SRRIP inserts: " << srrip_inserts << "\n";
    std::cout << "BRRIP inserts: " << brrip_inserts << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DRRIP+Dead heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", SRRIP_inserts=" << srrip_inserts
              << ", BRRIP_inserts=" << brrip_inserts
              << ", decay_events=" << decay_events << "\n";
}