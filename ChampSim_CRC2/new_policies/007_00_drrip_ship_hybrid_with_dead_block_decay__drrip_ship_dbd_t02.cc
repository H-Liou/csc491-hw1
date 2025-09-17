#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel;
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower

// --- SHiP-lite Metadata ---
#define SIG_BITS 6
#define SHIP_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Dead-block counter (1 bit per block) ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 1 bit per block

// --- Periodic decay ---
uint64_t access_counter = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // SRRIP default insertion
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start at weak reuse
    memset(dead_ctr, 0, sizeof(dead_ctr));
    psel = (1 << (PSEL_BITS - 1));
    // Assign leader sets: evenly distributed
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS / 2) leader_set_type[s] = 0; // SRRIP
        else if (s < NUM_LEADER_SETS) leader_set_type[s] = 1; // BRRIP
        else leader_set_type[s] = 2; // follower
    }
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>(PC ^ (PC >> 6)) & ((1 << SIG_BITS) - 1);
}

// --- Victim selection: prefer dead blocks ---
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
    // Prefer blocks marked dead
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 && dead_ctr[set][way])
            return way;
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

// --- Dead-block counter decay (periodic) ---
inline void deadblock_decay() {
    if ((access_counter & 0xFFF) == 0) { // every 4096 LLC accesses
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                dead_ctr[set][way] = 0;
    }
}

// --- SHiP counter decay (periodic) ---
inline void ship_decay() {
    if ((access_counter & 0xFFF) == 0) { // every 4096 LLC accesses
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (ship_ctr[set][way] > 0)
                    ship_ctr[set][way]--;
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
    access_counter++;
    if ((access_counter & 0xFFF) == 0) {
        ship_decay();
        deadblock_decay();
    }

    uint8_t sig = get_signature(PC);

    // On hit: promote block, increment reuse counter, mark alive
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        dead_ctr[set][way] = 0; // block is alive
        return;
    }

    // --- DRRIP set-dueling: choose insertion depth ---
    uint8_t insertion_rrpv = 2; // default SRRIP
    if (leader_set_type[set] == 0) { // SRRIP leader
        insertion_rrpv = 2;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        insertion_rrpv = (rand() % 32 == 0) ? 0 : 2; // MRU with 1/32 probability
    } else { // follower
        insertion_rrpv = (psel >= (1 << (PSEL_BITS - 1))) ? 2 : ((rand() % 32 == 0) ? 0 : 2);
    }

    // --- SHiP bias: if strong reuse, override DRRIP and insert at MRU ---
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1;
    dead_ctr[set][way] = 0; // new block is alive

    // --- DIP PSEL update ---
    if (leader_set_type[set] == 0) { // SRRIP leader
        if (hit) { if (psel < ((1 << PSEL_BITS) - 1)) psel++; }
        else { if (psel > 0) psel--; }
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        if (hit) { if (psel > 0) psel--; }
        else { if (psel < ((1 << PSEL_BITS) - 1)) psel++; }
    }

    // --- Dead-block approximation: if block was not reused, mark dead ---
    if (!hit && ship_ctr[set][way] == 0)
        dead_ctr[set][way] = 1;
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int dead_blocks = 0, total_blocks = 0, strong_reuse = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w]) dead_blocks++;
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "DRRIP-SHIP-DBD Policy: DRRIP set-dueling + SHiP-lite + Dead-block Decay" << std::endl;
    std::cout << "Dead blocks detected: " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dead_ctr[s][w]) dead_blocks++;
            total_blocks++;
        }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << total_blocks << std::endl;
}