#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- DIP Metadata ----
// 2-bit LRU stack position per block (for LIP/BIP)
static uint8_t lru_stack[LLC_SETS][LLC_WAYS];

// 6-bit PSEL counter for DIP set-dueling (LIP vs BIP)
static uint8_t psel = 32; // 6 bits, initialized mid-range

// 32 leader sets: first 16 for LIP, next 16 for BIP
static const uint32_t NUM_LEADER_SETS = 32;
static uint32_t leader_sets_lip[16];
static uint32_t leader_sets_bip[16];

// ---- SHiP-lite Metadata ----
// 6-bit PC signature per block
static uint8_t block_signature[LLC_SETS][LLC_WAYS]; // 6 bits/block

// 2-bit outcome counter per signature (64 entries)
static uint8_t signature_outcome[64];

// ---- Dead-block Counter ----
// 2-bit dead-block counter per block
static uint8_t dead_counter[LLC_SETS][LLC_WAYS];

// ---- Helper: hash PC to 6-bit signature ----
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// ---- Initialization ----
void InitReplacementState() {
    memset(lru_stack, 0, sizeof(lru_stack));
    memset(block_signature, 0, sizeof(block_signature));
    memset(signature_outcome, 1, sizeof(signature_outcome)); // weak reuse default
    memset(dead_counter, 0, sizeof(dead_counter));

    // Pick leader sets: evenly spread across LLC_SETS
    for (uint32_t i = 0; i < 16; ++i) {
        leader_sets_lip[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
        leader_sets_bip[i] = (LLC_SETS / NUM_LEADER_SETS) * (i + 16);
    }
}

// ---- Find victim: prefer dead blocks, else LRU ----
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer block with dead_counter==3 (most dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_counter[set][way] == 3)
            return way;
    // Else, pick LRU (highest lru_stack value)
    uint32_t lru_way = 0, max_lru = lru_stack[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (lru_stack[set][way] > max_lru) {
            max_lru = lru_stack[set][way];
            lru_way = way;
        }
    }
    return lru_way;
}

// ---- Update replacement state ----
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
    // SHiP signature
    uint8_t sig = GetSignature(PC);

    // DIP set-dueling: check if this set is a leader
    bool is_lip_leader = false, is_bip_leader = false;
    for (uint32_t i = 0; i < 16; ++i) {
        if (set == leader_sets_lip[i]) is_lip_leader = true;
        if (set == leader_sets_bip[i]) is_bip_leader = true;
    }

    // On hit: promote to MRU, update SHiP outcome, reset dead-counter
    if (hit) {
        // Move to MRU (lru_stack=0), increment others
        uint8_t old_lru = lru_stack[set][way];
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (lru_stack[set][w] < old_lru)
                lru_stack[set][w]++;
        lru_stack[set][way] = 0;

        if (signature_outcome[sig] < 3) ++signature_outcome[sig];
        dead_counter[set][way] = 0;
        return;
    }

    // On miss: update SHiP outcome for victim block, increment dead-counter
    uint8_t victim_sig = block_signature[set][way];
    if (signature_outcome[victim_sig] > 0) --signature_outcome[victim_sig];
    if (dead_counter[set][way] < 3) ++dead_counter[set][way];

    // --- Insertion Policy ---
    // If strong SHiP reuse, insert at MRU (lru_stack=0)
    if (signature_outcome[sig] >= 2) {
        // Move all blocks' lru_stack up, insert at MRU
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            lru_stack[set][w]++;
        lru_stack[set][way] = 0;
    } else {
        // DIP: select LIP or BIP insertion
        bool insert_lru = false;
        if (is_lip_leader) {
            insert_lru = true;
        } else if (is_bip_leader) {
            insert_lru = (rand() % 32 == 0); // BIP: insert at LRU 1/32 times
        } else {
            insert_lru = (psel < 32) ? true : (rand() % 32 == 0);
        }
        if (insert_lru) {
            // Insert at LRU (max lru_stack)
            uint8_t max_lru = 0;
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (lru_stack[set][w] > max_lru)
                    max_lru = lru_stack[set][w];
            lru_stack[set][way] = max_lru;
        } else {
            // Insert at MRU
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                lru_stack[set][w]++;
            lru_stack[set][way] = 0;
        }
    }
    // Track signature for inserted block
    block_signature[set][way] = sig;
    dead_counter[set][way] = 0;

    // --- DIP PSEL update ---
    // If this set is a leader, update PSEL based on hit/miss
    if (is_lip_leader && !hit) {
        if (psel < 63) ++psel;
    } else if (is_bip_leader && !hit) {
        if (psel > 0) --psel;
    }

    // --- Dead-block decay: every 4096 misses, decay all counters ---
    static uint64_t miss_count = 0;
    miss_count++;
    if ((miss_count & 0xFFF) == 0) { // every 4096 misses
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_counter[s][w] > 0) --dead_counter[s][w];
    }
}

// ---- Print statistics ----
void PrintStats() {
    uint32_t strong_sig = 0;
    for (uint32_t i = 0; i < 64; ++i)
        if (signature_outcome[i] >= 2) ++strong_sig;
    uint32_t dead_blocks = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_counter[i][w] == 3) ++dead_blocks;
    std::cout << "DSD-Decay Policy\n";
    std::cout << "Strong reuse signatures: " << strong_sig << " / 64\n";
    std::cout << "Dead blocks (counter==3): " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << "\n";
    std::cout << "PSEL: " << (uint32_t)psel << " (LIP if <32, BIP if >=32)\n";
}

// ---- Heartbeat stats ----
void PrintStats_Heartbeat() {
    uint32_t dead_blocks = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_counter[i][w] == 3) ++dead_blocks;
    std::cout << "[Heartbeat] Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << "\n";
}