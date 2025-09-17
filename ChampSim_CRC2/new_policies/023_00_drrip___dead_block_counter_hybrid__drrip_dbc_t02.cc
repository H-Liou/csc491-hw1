#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block counter: 2-bit per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// --- DRRIP set-dueling: 10-bit PSEL, 64 leader sets ---
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t psel = PSEL_MAX / 2;
#define NUM_LEADER_SETS 64
// Leader sets: first 32 for SRRIP, next 32 for BRRIP
bool is_leader_set(uint32_t set, bool &is_srrip_leader, bool &is_brrip_leader) {
    is_srrip_leader = (set < NUM_LEADER_SETS / 2);
    is_brrip_leader = (set >= NUM_LEADER_SETS / 2 && set < NUM_LEADER_SETS);
    return is_srrip_leader || is_brrip_leader;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    psel = PSEL_MAX / 2;
}

// --- Find victim: SRRIP (victim with RRPV==3) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

// --- Update replacement state ---
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
    // --- Dead-block counter update ---
    if (hit) {
        dead_ctr[set][way] = 0; // reset on reuse
        rrpv[set][way] = 0;     // MRU on hit
        return;
    }

    // On eviction: increment dead-block counter for victim block
    if (dead_ctr[set][way] < 3)
        dead_ctr[set][way]++;

    // --- DRRIP set-dueling ---
    bool is_srrip_leader = false, is_brrip_leader = false;
    bool leader = is_leader_set(set, is_srrip_leader, is_brrip_leader);

    // Choose insertion policy
    uint8_t ins_rrpv = 2; // default SRRIP (insert at RRPV=2)

    // Dead-block counter: if block was dead (counter high), insert at distant RRPV
    if (dead_ctr[set][way] >= 2)
        ins_rrpv = 3;

    // DRRIP: set-dueling for leader sets
    if (leader) {
        if (is_srrip_leader)
            ins_rrpv = 2; // SRRIP: insert at RRPV=2
        else if (is_brrip_leader)
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at RRPV=3, 1/32 at RRPV=2
    } else {
        // Follower sets: use PSEL to choose
        if (psel >= (PSEL_MAX / 2))
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
    }

    // If dead-block counter is high, override to distant insert
    if (dead_ctr[set][way] >= 2)
        ins_rrpv = 3;

    rrpv[set][way] = ins_rrpv;

    // --- DRRIP: update PSEL on leader set hits ---
    if (leader) {
        if (hit) {
            if (is_srrip_leader && psel < PSEL_MAX) psel++;
            else if (is_brrip_leader && psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Counter Hybrid: Final statistics." << std::endl;
    uint32_t dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w] >= 2) dead_blocks++;
            total_blocks++;
        }
    std::cout << "Dead blocks (counter>=2): " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "PSEL value: " << psel << "/" << PSEL_MAX << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print dead-block fraction and PSEL
}