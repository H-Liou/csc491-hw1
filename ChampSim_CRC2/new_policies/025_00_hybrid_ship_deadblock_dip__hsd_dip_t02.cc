#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: Signature table ----
#define SHIP_TABLE_SIZE 1024 // 1024 entries, 6-bit index (PC % 1024)
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- Per-line dead-block counter ----
uint8_t dead_count[LLC_SETS][LLC_WAYS]; // 2 bits per line

// ---- DIP-style set-dueling ----
#define NUM_LEADER_SETS 32
uint8_t is_lip_leader[LLC_SETS]; // 1 if LIP leader, 2 if BIP leader, 0 otherwise
uint16_t psel = 512; // 10 bits, 0-1023

// ---- Periodic decay for dead-block counters ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(dead_count, 0, sizeof(dead_count));
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    access_counter = 0;
    psel = 512;

    // Assign leader sets: evenly spread
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_lip_leader[i] = 1; // LIP leader
        is_lip_leader[NUM_LEADER_SETS + i] = 2; // BIP leader
    }
}

// Find victim in the set
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

    // Prefer blocks with dead_count == 0 and max RRPV
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 && dead_count[set][way] == 0)
            return way;

    // RRIP: select block with max RRPV
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
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
    access_counter++;

    // ---- SHiP signature extraction ----
    uint16_t sig = (uint16_t)((PC >> 2) & 0x3F); // 6 bits
    uint16_t ship_idx = sig;
    line_sig[set][way] = sig;

    // ---- SHiP outcome update ----
    if (hit) {
        // On hit, promote block and increment reuse counter
        rrpv[set][way] = 0;
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
        if (dead_count[set][way] < 3)
            dead_count[set][way]++;
    } else {
        // On miss/evict, penalize previous signature
        uint16_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
        // Decay dead-block counter
        if (dead_count[set][way] > 0)
            dead_count[set][way]--;
    }

    // ---- DIP-style insertion depth control ----
    uint8_t insertion_rrpv = 3; // default: insert at LRU

    // SHiP: High-reuse PC signatures insert at MRU
    if (ship_table[ship_idx].reuse_counter >= 2)
        insertion_rrpv = 0;

    // DIP set-dueling: leader sets update PSEL
    if (is_lip_leader[set] == 1) { // LIP leader
        insertion_rrpv = 3;
        if (hit) { if (psel < 1023) psel++; }
        else     { if (psel > 0)    psel--; }
    }
    else if (is_lip_leader[set] == 2) { // BIP leader
        // BIP: insert at MRU only 1/32 fills, else LRU
        static uint64_t bip_ctr = 0;
        if ((bip_ctr++ % 32) == 0) insertion_rrpv = 0;
        else insertion_rrpv = 3;
        if (hit) { if (psel > 0)    psel--; }
        else     { if (psel < 1023) psel++; }
    }
    else {
        // Non-leader sets: choose policy by PSEL
        if (psel >= 512) {
            // Favor LIP (LRU insertion)
            insertion_rrpv = 3;
        } else {
            // Favor BIP (MRU insertion 1/32 fills)
            static uint64_t bip_ctr2 = 0;
            if ((bip_ctr2++ % 32) == 0) insertion_rrpv = 0;
            else insertion_rrpv = 3;
        }
    }

    // SHiP overrides DIP for high-reuse PCs
    if (ship_table[ship_idx].reuse_counter >= 2)
        insertion_rrpv = 0;

    rrpv[set][way] = insertion_rrpv;
    line_sig[set][way] = sig;
    // Reset dead-block counter on fill
    if (!hit)
        dead_count[set][way] = 0;

    // ---- Periodic decay of dead-block counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_count[s][w] > 0)
                    dead_count[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int dead_blocks = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int j = 0; j < LLC_WAYS; ++j)
            if (dead_count[i][j] == 0) dead_blocks++;
    std::cout << "HSD-DIP Policy: Hybrid SHiP-Deadblock DIP" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Blocks predicted dead: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int dead_blocks = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int j = 0; j < LLC_WAYS; ++j)
            if (dead_count[i][j] == 0) dead_blocks++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Blocks predicted dead (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value (heartbeat): " << psel << std::endl;
}