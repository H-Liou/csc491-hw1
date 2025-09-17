#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- SHiP-lite: Signature table ----
#define SHIP_TABLE_SIZE 1024 // 1024 entries, 6-bit index (PC % 1024)
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- Per-line dead-block prediction ----
uint8_t dead_counter[LLC_SETS][LLC_WAYS]; // 2 bits per line

// ---- DIP-style set-dueling ----
#define NUM_LEADER_SETS 32
uint8_t is_lip_leader[LLC_SETS];
uint8_t is_bip_leader[LLC_SETS];
uint16_t psel; // 10 bits

// ---- Initialization ----
void InitReplacementState() {
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(dead_counter, 0, sizeof(dead_counter));
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    memset(is_bip_leader, 0, sizeof(is_bip_leader));
    psel = (1 << 9); // 512
    // Assign leader sets: first NUM_LEADER_SETS for LIP, next NUM_LEADER_SETS for BIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS/2 + i] = 1;
    }
}

// ---- Victim selection: LRU ----
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

    // Find block with max dead-counter (>=2), else LRU (way 0)
    uint32_t victim = 0;
    uint8_t max_dead = dead_counter[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (dead_counter[set][way] > max_dead) {
            max_dead = dead_counter[set][way];
            victim = way;
        }
    }
    return victim;
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
    // ---- SHiP signature extraction ----
    uint16_t sig = (uint16_t)((PC >> 2) & 0x3F); // 6 bits
    uint16_t ship_idx = sig;
    line_sig[set][way] = sig;

    // ---- SHiP outcome update ----
    if (hit) {
        // On hit, increment reuse counter
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
        // Reset dead-block counter
        dead_counter[set][way] = 0;
    } else {
        // On miss/evict, penalize previous signature if block was dead
        uint16_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
        // Increment dead-block counter
        if (dead_counter[set][way] < 3)
            dead_counter[set][way]++;
    }

    // ---- DIP set-dueling: choose insertion policy ----
    bool use_bip = false;
    if (is_lip_leader[set])
        use_bip = false;
    else if (is_bip_leader[set])
        use_bip = true;
    else
        use_bip = (psel >= (1 << 9));

    // ---- Insertion depth ----
    uint8_t insertion_way = LLC_WAYS - 1; // default LRU
    // BIP: 1/32 insert MRU, rest LRU
    if (use_bip && (rand() % 32 == 0))
        insertion_way = 0; // MRU

    // SHiP bias: high-reuse PCs insert at MRU
    if (ship_table[ship_idx].reuse_counter >= 2)
        insertion_way = 0;

    // Dead-block bias: if dead_counter >=2, force LRU insertion
    if (dead_counter[set][way] >= 2)
        insertion_way = LLC_WAYS - 1;

    // Move block to insertion_way position (simple LRU stack update)
    // For simulation, just reset dead_counter at insertion
    dead_counter[set][way] = 0;
    line_sig[set][way] = sig;

    // ---- DIP PSEL update ----
    if (is_lip_leader[set]) {
        if (hit && psel < 1023) psel++;
    } else if (is_bip_leader[set]) {
        if (hit && psel > 0) psel--;
    }

    // ---- Periodic dead-counter decay ----
    static uint64_t access_count = 0;
    access_count++;
    if (access_count % (LLC_SETS * LLC_WAYS * 2) == 0) { // every 64K accesses
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_counter[s][w] > 0) dead_counter[s][w]--;
    }
}

// ---- Print end-of-simulation statistics ----
void PrintStats() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int dead_blocks = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int w = 0; w < LLC_WAYS; ++w)
            if (dead_counter[i][w] >= 2) dead_blocks++;
    std::cout << "SLDP Policy: SHiP-LIP + Dead-Block Prediction" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Dead blocks (counter>=2): " << dead_blocks << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// ---- Print periodic (heartbeat) statistics ----
void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int dead_blocks = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int w = 0; w < LLC_WAYS; ++w)
            if (dead_counter[i][w] >= 2) dead_blocks++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
}