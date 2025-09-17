#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP Metadata ---
#define PSEL_BITS 10
#define NUM_LEADER_SETS 32
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // 10-bit PSEL, start at midpoint
uint8_t is_leader_set[LLC_SETS];        // 0: follower, 1: LIP leader, 2: BIP leader

// --- SHiP-lite Metadata ---
#define SIG_BITS 6
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Dead-block Approximation ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block, decays periodically

// --- Periodic Decay Counter ---
#define DECAY_PERIOD 8192
uint64_t access_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr));
    memset(dead_ctr, 2, sizeof(dead_ctr)); // Start at mid value
    memset(is_leader_set, 0, sizeof(is_leader_set));

    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = 1; // LIP leader
        is_leader_set[LLC_SETS - 1 - i] = 2; // BIP leader
    }
    PSEL = (1 << (PSEL_BITS - 1));
    access_count = 0;
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// --- Victim selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // RRIP victim selection
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
    uint8_t sig = get_signature(PC);

    // --- Update SHiP-lite ---
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        return;
    }

    // --- DIP Set-dueling: update PSEL if leader set ---
    if (is_leader_set[set] == 1) { // LIP leader
        if (hit) {
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        }
    }
    else if (is_leader_set[set] == 2) { // BIP leader
        if (hit) {
            if (PSEL > 0) PSEL--;
        }
    }

    // --- Insertion policy ---
    uint8_t insertion_rrpv = 3; // Default: LIP (insert at LRU)

    // DIP: followers use PSEL to choose LIP or BIP
    if (is_leader_set[set] == 0) {
        if (PSEL >= (1 << (PSEL_BITS - 1))) {
            insertion_rrpv = 3; // LIP: insert at LRU
        } else {
            // BIP: insert at MRU with low probability (1/32)
            insertion_rrpv = ((rand() % 32) == 0) ? 0 : 3;
        }
    }
    // Leader sets: fixed policy
    else if (is_leader_set[set] == 1) {
        insertion_rrpv = 3; // LIP
    }
    else if (is_leader_set[set] == 2) {
        insertion_rrpv = ((rand() % 32) == 0) ? 0 : 3; // BIP
    }

    // SHiP bias: strong reuse (ctr>=2) → insert at MRU
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    // Dead-block detection: if dead_ctr==0, force LRU insertion
    if (dead_ctr[set][way] == 0)
        insertion_rrpv = 3;

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // weak reuse on fill

    // Dead-block approximation: reset/reduce on fill
    dead_ctr[set][way] = 1;
    
    // --- Periodic decay of dead_ctr ---
    access_count++;
    if ((access_count % DECAY_PERIOD) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dead_ctr[s][w] == 0) dead_blocks++;
            total_blocks++;
        }
    std::cout << "PASDD Policy: Phase-Aware SHiP-DIP Hybrid + Dead-Block Decay" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Dead block candidates (dead_ctr==0): " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dead_ctr[s][w] == 0) dead_blocks++;
            total_blocks++;
        }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << std::endl;
}