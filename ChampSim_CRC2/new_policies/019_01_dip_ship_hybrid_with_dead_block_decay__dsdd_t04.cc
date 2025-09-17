#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ----- DIP Metadata -----
#define NUM_LEADER_SETS 64
uint8_t is_lip_leader[LLC_SETS];
uint8_t is_bip_leader[LLC_SETS];
uint16_t psel; // 10-bit PSEL

// ----- SHiP-lite Metadata -----
#define SIG_BITS 6
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2 bits per block

// ----- Dead-block Counter Metadata -----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 1 bit per block (0=alive, 1=dead)
uint32_t decay_tick = 0;
#define DECAY_PERIOD 8192 // Decay every 8192 fills

// ----- LRU Stack Metadata -----
uint8_t lru_stack[LLC_SETS][LLC_WAYS]; // 4 bits per block

// ----- Initialization -----
void InitReplacementState() {
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(lru_stack, 0, sizeof(lru_stack));
    psel = (1 << 9); // initialize to midpoint (512)
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    memset(is_bip_leader, 0, sizeof(is_bip_leader));
    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS/2 + i] = 1;
    }
}

// ----- PC Signature hashing -----
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// ----- LRU Stack Update -----
void update_lru(uint32_t set, uint32_t way) {
    uint8_t old_lru = lru_stack[set][way];
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (lru_stack[set][w] < old_lru)
            lru_stack[set][w]++;
    }
    lru_stack[set][way] = 0;
}

// ----- Find LRU block -----
uint32_t find_lru(uint32_t set) {
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (lru_stack[set][way] == LLC_WAYS - 1)
            return way;
    // Should not happen
    return 0;
}

// ----- Find BIP block (LRU except 5% MRU) -----
uint32_t find_bip(uint32_t set) {
    // 5% of the time, insert at MRU (way with lru_stack==0)
    if (rand() % 100 < 5) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (lru_stack[set][way] == 0)
                return way;
    }
    // Otherwise, LRU
    return find_lru(set);
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

    // Dead-block: prefer dead blocks first
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 1)
            return way;

    // Otherwise, LRU
    return find_lru(set);
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

    // --- Dead-block decay ---
    decay_tick++;
    if (decay_tick % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_ctr[s][w] = 0; // reset all to alive
    }

    // --- SHiP update ---
    if (hit) {
        update_lru(set, way);
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        dead_ctr[set][way] = 0; // block is alive
        return;
    } else {
        if (ship_ctr[set][way] > 0) ship_ctr[set][way]--;
        dead_ctr[set][way] = 1; // block is dead on miss
    }

    // --- DIP insertion depth selection ---
    bool use_lip = false;
    if (is_lip_leader[set])
        use_lip = true;
    else if (is_bip_leader[set])
        use_lip = false;
    else
        use_lip = (psel < (1 << 9)); // favor LIP if psel < 512

    // --- SHiP bias: strong reuse (ctr>=2) → insert at MRU ---
    bool ship_strong = (ship_ctr[set][way] >= 2);

    // --- Dead-block override: if dead_ctr==1, always insert at LRU ---
    if (dead_ctr[set][way] == 1) {
        // Insert at LRU
        uint32_t lru_way = find_lru(set);
        lru_stack[set][lru_way] = LLC_WAYS - 1;
        ship_signature[set][lru_way] = sig;
        ship_ctr[set][lru_way] = 1;
        dead_ctr[set][lru_way] = 0;
        return;
    }

    // --- DIP+SHiP insertion ---
    if (ship_strong) {
        // Insert at MRU
        update_lru(set, way);
    } else {
        if (use_lip) {
            // Insert at LRU
            lru_stack[set][way] = LLC_WAYS - 1;
        } else {
            // Insert at LRU except 5% MRU (BIP)
            if (rand() % 100 < 5)
                update_lru(set, way);
            else
                lru_stack[set][way] = LLC_WAYS - 1;
        }
    }
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1;
    dead_ctr[set][way] = 0;

    // --- DIP set-dueling PSEL update ---
    if (is_lip_leader[set]) {
        if (hit && psel < 1023) psel++;
    } else if (is_bip_leader[set]) {
        if (hit && psel > 0) psel--;
    }
}

// ----- Print end-of-simulation statistics -----
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dead_ctr[s][w] == 1) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "DSDD Policy: DIP-SHiP Hybrid + Dead-block Decay" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Blocks marked dead: " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// ----- Print periodic (heartbeat) statistics -----
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dead_ctr[s][w] == 1) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << total_blocks << std::endl;
}