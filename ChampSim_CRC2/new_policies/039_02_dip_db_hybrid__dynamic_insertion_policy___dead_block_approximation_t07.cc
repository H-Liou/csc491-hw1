#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Dead-block counters ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Set-dueling DIP (LIP vs BIP) ----
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 512;
uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: LIP, 1: BIP
std::vector<uint32_t> leader_sets;

// Helper: is this set a leader set? Returns 0=LIP, 1=BIP, 2=Follower
uint8_t GetSetType(uint32_t set) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set)
            return leader_set_type[i];
    return 2; // Follower
}

void InitReplacementState() {
    // RRIP, dead-block counter
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // Default distant
            dead_ctr[set][way] = 1; // Neutral
        }
    // Leader sets: evenly spread across LLC_SETS
    leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = (i * LLC_SETS) / NUM_LEADER_SETS;
        leader_sets.push_back(set);
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // First half LIP, second half BIP
    }
    PSEL = 512;
}

// Find victim in the set (dead-block approximation)
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

    // Prefer block with dead_ctr==0 (approximate dead block)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 0)
            return way;

    // Prefer block with RRPV=3 (classic RRIP)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
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
    // --- Dead-block approximation ---
    // On hit: bump dead_ctr up to max (3)
    if (hit) {
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
        // Protect block: reset RRPV to 0 (MRU)
        rrpv[set][way] = 0;
    } else {
        // On miss: decay victim block's dead_ctr
        if (dead_ctr[set][way] > 0)
            dead_ctr[set][way]--;
    }

    // --- Periodic decay: every N accesses, decay all dead_ctr by 1 (simulate liveness window) ---
    static uint64_t access_count = 0;
    access_count++;
    if (access_count % (LLC_SETS * LLC_WAYS) == 0) { // every LLC-size accesses
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }

    // --- Set-dueling: leader sets update PSEL ---
    uint8_t set_type = GetSetType(set);
    if (!hit && set_type < 2) {
        if (set_type == 0) { // LIP leader miss: increment PSEL
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        } else if (set_type == 1) { // BIP leader miss: decrement PSEL
            if (PSEL > 0) PSEL--;
        }
    }

    // --- Insertion policy ---
    uint8_t insert_rrpv = 2; // Default distant
    if (set_type == 0) { // LIP leader
        insert_rrpv = 0; // Insert at MRU (likely reused)
    } else if (set_type == 1) { // BIP leader
        // Insert mostly at distant, occasionally at MRU (BIP: 1/32 at MRU)
        static uint32_t bip_ctr = 0;
        bip_ctr++;
        insert_rrpv = (bip_ctr % 32 == 0) ? 0 : 2;
    } else { // Follower
        insert_rrpv = (PSEL >= 512) ?
            0 : // LIP (insert MRU)
            ((rand() % 32 == 0) ? 0 : 2); // BIP (mostly distant, 1/32 at MRU)
    }
    rrpv[set][way] = insert_rrpv;
    // On miss, reset dead_ctr to neutral
    if (!hit)
        dead_ctr[set][way] = 1;
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks = 0, live_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_ctr[set][way] == 0) dead_blocks++;
            if (dead_ctr[set][way] == 3) live_blocks++;
        }
    std::cout << "DIP-DB Hybrid Policy (DIP + Dead-block Approximation)" << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Strongly live blocks: " << live_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int live_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) live_blocks++;
    std::cout << "Live blocks (heartbeat): " << live_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}