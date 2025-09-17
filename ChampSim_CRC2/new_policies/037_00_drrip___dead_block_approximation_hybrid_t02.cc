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
#define SRRIP_INSERT 2
#define BRRIP_INSERT_PROB 32 // 1/32 chance to insert at RRPV=2, else RRPV=3

#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)

// Leader sets for set-dueling
#define NUM_LEADER_SETS 32
#define LEADER_SET_STRIDE (LLC_SETS / NUM_LEADER_SETS)

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX 3
#define DEAD_DECAY_INTERVAL 4096 // Decay every N accesses

// Metadata
std::vector<uint8_t> block_rrpv;      // Per-block RRPV
std::vector<uint8_t> block_dead;      // Per-block dead-block counter
std::vector<uint8_t> set_type;        // Per-set: 0=Follower, 1=SRRIP Leader, 2=BRRIP Leader
uint16_t psel = PSEL_INIT;            // DRRIP set-dueling selector

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t dead_bypass = 0;

// Helper: assign leader sets
void assign_leader_sets() {
    set_type.resize(LLC_SETS, 0);
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        set_type[i * LEADER_SET_STRIDE] = 1; // SRRIP leader
        set_type[i * LEADER_SET_STRIDE + 1] = 2; // BRRIP leader
    }
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_dead.resize(LLC_SETS * LLC_WAYS, 0);
    assign_leader_sets();
    psel = PSEL_INIT;
    access_counter = 0;
    hits = 0;
    dead_bypass = 0;
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
    // Dead-block bypass: if any block's dead counter is saturated, prefer it
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
        if (block_rrpv[idx] < RRPV_MAX)
            block_rrpv[idx]++;
    }
    // Second pass
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

    // Decay dead-block counters periodically
    if ((access_counter & (DEAD_DECAY_INTERVAL - 1)) == 0) {
        for (size_t i = 0; i < block_dead.size(); i++) {
            if (block_dead[i] > 0)
                block_dead[i]--;
        }
    }

    // On hit: promote to MRU, reset dead-block counter
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        block_dead[idx] = 0;
        return;
    }

    // Dead-block bypass: if victim block's dead counter is saturated, do not install (simulate bypass)
    if (block_dead[idx] == DEAD_MAX) {
        dead_bypass++;
        block_rrpv[idx] = RRPV_MAX;
        return;
    }

    // DRRIP insertion policy
    uint8_t insert_rrpv = RRPV_MAX;
    if (set_type[set] == 1) { // SRRIP leader
        insert_rrpv = SRRIP_INSERT;
    } else if (set_type[set] == 2) { // BRRIP leader
        insert_rrpv = (rand() % BRRIP_INSERT_PROB == 0) ? SRRIP_INSERT : RRPV_MAX;
    } else { // Follower set
        insert_rrpv = (psel >= (PSEL_MAX / 2)) ?
            SRRIP_INSERT :
            ((rand() % BRRIP_INSERT_PROB == 0) ? SRRIP_INSERT : RRPV_MAX);
    }
    block_rrpv[idx] = insert_rrpv;

    // On miss: increment dead-block counter
    if (!hit && block_dead[idx] < DEAD_MAX)
        block_dead[idx]++;

    // Set-dueling: update PSEL on leader set misses
    if (set_type[set] == 1 && !hit) { // SRRIP leader miss
        if (psel < PSEL_MAX) psel++;
    }
    if (set_type[set] == 2 && !hit) { // BRRIP leader miss
        if (psel > 0) psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Approximation Hybrid Policy\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Dead-block bypass events: " << dead_bypass << "\n";
    std::cout << "Final PSEL: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DRRIP+Dead heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", dead_bypass=" << dead_bypass
              << ", PSEL=" << psel << "\n";
}