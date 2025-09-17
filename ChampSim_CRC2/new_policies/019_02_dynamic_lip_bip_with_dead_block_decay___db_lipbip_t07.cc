#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

// Policy: Dynamic LIP-BIP with Dead-Block Decay

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// -- DIP Metadata --
static uint8_t psel = 512; // 10-bit PSEL (0..1023), initialized mid
static const uint32_t NUM_LEADER_SETS = 64;
static uint32_t leader_sets_lip[32];
static uint32_t leader_sets_bip[32];

// -- Dead-block Predictor: 2 bits per block, decayed periodically --
static uint8_t dead_counter[LLC_SETS][LLC_WAYS]; // 2 bits per block (~8 KiB)
static uint32_t access_counter = 0; // for periodic decay

// -- Replacement State: LRU stack position per block (4 bits/block) --
static uint8_t lru_stack[LLC_SETS][LLC_WAYS]; // 4 bits/block (~16 KiB)

// -- Helper: Find way with highest LRU position --
inline uint32_t GetLRUVictim(uint32_t set) {
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (lru_stack[set][way] == (LLC_WAYS - 1))
            return way;
    // Should not happen
    return 0;
}

// -- Helper: Update LRU stack on access/insert --
inline void UpdateLRU(uint32_t set, uint32_t way) {
    uint8_t pos = lru_stack[set][way];
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (lru_stack[set][w] < pos)
            lru_stack[set][w]++;
    }
    lru_stack[set][way] = 0;
}

// -- Initialization --
void InitReplacementState() {
    memset(dead_counter, 0, sizeof(dead_counter));
    access_counter = 0;
    // LRU stack: initialize to unique positions
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            lru_stack[set][way] = way;

    // Pick leader sets, evenly spread
    for (uint32_t i = 0; i < 32; ++i) {
        leader_sets_lip[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
        leader_sets_bip[i] = (LLC_SETS / NUM_LEADER_SETS) * (i + 32);
    }
    psel = 512;
}

// -- Find victim: pure LRU --
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    return GetLRUVictim(set); // block with highest LRU stack position
}

// -- Update replacement state --
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
    // Every 8192 accesses: decay all dead counters (decay to zero if idle)
    // Decay is simple: decrement if >0
    if ((access_counter & 0x1FFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_counter[s][w] > 0) --dead_counter[s][w];
    }

    // Leader set detection
    bool is_lip_leader = false, is_bip_leader = false;
    for (uint32_t i = 0; i < 32; ++i) {
        if (set == leader_sets_lip[i]) is_lip_leader = true;
        if (set == leader_sets_bip[i]) is_bip_leader = true;
    }

    // Dead-block counter for victim: increment if evicted, reset on hit
    if (!hit) {
        if (dead_counter[set][way] < 3) dead_counter[set][way]++;
    } else {
        dead_counter[set][way] = 0;
    }

    // --- Insertion Policy ---
    uint8_t ins_pos = 0; // MRU

    // If block's dead_counter saturates, always insert at LRU (aggressive eviction)
    if (dead_counter[set][way] >= 2) {
        ins_pos = LLC_WAYS - 1; // LRU
    } else {
        // DIP set-dueling: select LIP or BIP
        if (is_lip_leader) {
            ins_pos = LLC_WAYS - 1; // LIP: always LRU
        } else if (is_bip_leader) {
            ins_pos = (rand() % 32 == 0) ? (LLC_WAYS - 1) : 0; // BIP: 1/32 LRU, else MRU
        } else {
            // Use PSEL for followers: >=512 -> BIP, <512 -> LIP
            if (psel >= 512)
                ins_pos = (rand() % 32 == 0) ? (LLC_WAYS - 1) : 0;
            else
                ins_pos = LLC_WAYS - 1;
        }
    }
    // Update LRU stack: insert block at ins_pos, others shift accordingly
    // Find block(s) with ins_pos, swap stack positions
    uint32_t evict_way = way;
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        if (lru_stack[set][w] == ins_pos)
            evict_way = w;

    lru_stack[set][way] = ins_pos;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (w == way) continue;
        if (lru_stack[set][w] < ins_pos)
            lru_stack[set][w]++;
    }

    // -- DIP: update PSEL for leader sets on miss only --
    if (is_lip_leader && !hit) {
        if (psel > 0) --psel;
    } else if (is_bip_leader && !hit) {
        if (psel < 1023) ++psel;
    }
}

// -- Print statistics --
void PrintStats() {
    uint32_t dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_counter[set][way] >= 2) ++dead_blocks;
    std::cout << "DB-LIPBIP Policy\n";
    std::cout << "High dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << "\n";
    std::cout << "PSEL: " << psel << " (BIP if >=512, LIP if <512)\n";
}

// -- Heartbeat stats --
void PrintStats_Heartbeat() {
    uint32_t dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_counter[set][way] >= 2) ++dead_blocks;
    std::cout << "[Heartbeat] High dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << "\n";
}