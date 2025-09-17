#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP set-dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 8
uint8_t psel;
uint8_t leader_set_type[LLC_SETS]; // 0: LIP, 1: BIP, 2: follower

// --- SHiP-lite Metadata ---
#define SIG_BITS 5
#define SHIP_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 5-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- Dead-block Metadata ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- LRU Stack Position ---
uint8_t lru_stack[LLC_SETS][LLC_WAYS]; // 4 bits per block (for LRU/BIP/LIP)

// --- Periodic Decay ---
uint64_t global_access_counter = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start at weak reuse
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(lru_stack, 0, sizeof(lru_stack));
    psel = (1 << (PSEL_BITS - 1));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS / 2) leader_set_type[s] = 0; // LIP
        else if (s < NUM_LEADER_SETS) leader_set_type[s] = 1; // BIP
        else leader_set_type[s] = 2; // follower
    }
    global_access_counter = 0;
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 5)) & ((1 << SIG_BITS) - 1));
}

// --- Find LRU victim ---
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
    // Find block with max lru_stack value (LRU)
    uint8_t max_lru = 0;
    uint32_t victim = 0;
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (lru_stack[set][way] >= max_lru) {
            max_lru = lru_stack[set][way];
            victim = way;
        }
    }
    return victim;
}

// --- Update LRU stack ---
void update_lru_stack(uint32_t set, uint32_t way) {
    uint8_t old_pos = lru_stack[set][way];
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (lru_stack[set][w] < old_pos)
            lru_stack[set][w]++;
    }
    lru_stack[set][way] = 0;
}

// --- Dead-block periodic decay ---
void decay_dead_counters() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] > 0)
                dead_ctr[s][w]--;
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
    global_access_counter++;
    if ((global_access_counter & 0xFFF) == 0) // Every 4096 accesses
        decay_dead_counters();

    uint8_t sig = get_signature(PC);

    // On hit: promote block, increment reuse counter, reset dead counter
    if (hit) {
        update_lru_stack(set, way);
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        dead_ctr[set][way] = 0;
        return;
    }

    // On eviction: increment dead counter for victim
    dead_ctr[set][way] = (dead_ctr[set][way] < 3) ? dead_ctr[set][way] + 1 : 3;

    // --- DIP set-dueling: choose insertion depth ---
    uint8_t insertion_lru = LLC_WAYS - 1; // LRU default
    if (leader_set_type[set] == 0) { // LIP leader
        insertion_lru = LLC_WAYS - 1;
    } else if (leader_set_type[set] == 1) { // BIP leader
        insertion_lru = (rand() % 32 == 0) ? 0 : (LLC_WAYS - 1); // MRU with 1/32 probability
    } else { // follower
        insertion_lru = (psel >= (1 << (PSEL_BITS - 1))) ? (LLC_WAYS - 1) : ((rand() % 32 == 0) ? 0 : (LLC_WAYS - 1));
    }

    // --- SHiP bias: if strong reuse, override and insert at MRU ---
    if (ship_ctr[set][way] >= 2)
        insertion_lru = 0;

    // --- Dead-block bias: if dead counter == 3, force LRU insertion ---
    if (dead_ctr[set][way] == 3)
        insertion_lru = LLC_WAYS - 1;

    // Insert block at chosen LRU position
    uint8_t old_pos = lru_stack[set][way];
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (lru_stack[set][w] < old_pos)
            lru_stack[set][w]++;
    }
    lru_stack[set][way] = insertion_lru;

    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1;

    // --- DIP PSEL update ---
    if (leader_set_type[set] == 0) { // LIP leader
        if (hit) { if (psel < ((1 << PSEL_BITS) - 1)) psel++; }
        else { if (psel > 0) psel--; }
    } else if (leader_set_type[set] == 1) { // BIP leader
        if (hit) { if (psel > 0) psel--; }
        else { if (psel < ((1 << PSEL_BITS) - 1)) psel++; }
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int dead_blocks = 0, strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w] == 3) dead_blocks++;
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "DIP-SHiP-DBD Policy: DIP set-dueling + SHiP-lite + Dead-block Decay" << std::endl;
    std::cout << "Blocks with dead prediction (dead_ctr==3): " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "PSEL value: " << (uint32_t)psel << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int dead_blocks = 0, strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w] == 3) dead_blocks++;
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
}