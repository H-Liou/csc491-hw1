#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ----- DIP Metadata -----
uint8_t lip_leader[LLC_SETS];   // 64 leader sets for LIP
uint8_t bip_leader[LLC_SETS];   // 64 leader sets for BIP
uint16_t psel;                  // 10-bit PSEL

// ----- SHiP-lite Metadata -----
#define SIG_BITS 6
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2 bits per block

// ----- Dead-block Approximation -----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];       // 2 bits per block

// ----- Initialization -----
void InitReplacementState() {
    memset(lip_leader, 0, sizeof(lip_leader));
    memset(bip_leader, 0, sizeof(bip_leader));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr));
    memset(dead_ctr, 2, sizeof(dead_ctr));
    psel = (1 << 9); // 512 midpoint

    // Assign 64 leader sets for LIP and BIP
    for (uint32_t i = 0; i < 64; ++i) {
        lip_leader[i] = 1;
        bip_leader[LLC_SETS/2 + i] = 1;
    }
}

// ----- PC Signature hashing -----
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// ----- Victim selection -----
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

    // Dead-block first: evict block with dead_ctr==0 if any
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 0)
            return way;

    // Otherwise, evict true LRU (lowest ship_ctr, then lowest dead_ctr)
    uint32_t victim = 0;
    uint8_t min_ship = ship_ctr[set][0];
    uint8_t min_dead = dead_ctr[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (ship_ctr[set][way] < min_ship ||
            (ship_ctr[set][way] == min_ship && dead_ctr[set][way] < min_dead)) {
            victim = way;
            min_ship = ship_ctr[set][way];
            min_dead = dead_ctr[set][way];
        }
    }
    return victim;
}

// ----- Update replacement state -----
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

    // --- Dead-block counter decay: every 4096 fills, decay all counters in set ---
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) { // every 4096 fills
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[set][w] > 0) dead_ctr[set][w]--;
    }

    // --- SHiP update ---
    if (hit) {
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        return;
    } else {
        if (ship_ctr[set][way] > 0) ship_ctr[set][way]--;
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
    }

    // --- DIP insertion depth selection ---
    bool use_lip = false;
    if (lip_leader[set]) {
        use_lip = true;
    } else if (bip_leader[set]) {
        use_lip = false;
    } else {
        use_lip = (psel < (1 << 9)); // favor LIP if psel < 512
    }

    uint8_t insertion_way = LLC_WAYS - 1; // LRU
    if (!use_lip) {
        // BIP: insert at LRU with 5% probability, else MRU
        insertion_way = (rand() % 100 < 5) ? (LLC_WAYS - 1) : 0;
    }

    // --- SHiP bias: strong reuse (ctr>=2) → insert at MRU ---
    if (ship_ctr[set][way] >= 2)
        insertion_way = 0;

    // --- Insert block ---
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // weak reuse on fill
    dead_ctr[set][way] = 2; // moderate reuse on fill

    // --- DIP set-dueling PSEL update ---
    if (lip_leader[set]) {
        if (hit && psel < 1023) psel++;
    } else if (bip_leader[set]) {
        if (hit && psel > 0) psel--;
    }
}

// ----- Print end-of-simulation statistics -----
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dead_ctr[s][w] == 0) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "DSHD Policy: DIP-SHiP Hybrid + Dead-block Decay" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Blocks marked dead (dead_ctr==0): " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// ----- Print periodic (heartbeat) statistics -----
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dead_ctr[s][w] == 0) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << total_blocks << std::endl;
}