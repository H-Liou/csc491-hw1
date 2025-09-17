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
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- Dead-block approximation: 1-bit per line ----
uint8_t dead_bit[LLC_SETS][LLC_WAYS]; // 1 bit per block

// ---- Phase-adaptive DIP set-dueling ----
#define LEADER_SETS 64
uint8_t leader_flags[LLC_SETS]; // 0: normal, 1: LIP leader, 2: BIP leader
uint16_t psel; // 10 bits (0..1023)

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(dead_bit, 0, sizeof(dead_bit));
    memset(leader_flags, 0, sizeof(leader_flags));
    access_counter = 0;
    // Assign leader sets: evenly spaced, first 32 LIP, next 32 BIP
    for (uint32_t i = 0; i < LEADER_SETS; ++i) {
        uint32_t lip_set = (i * (LLC_SETS / (2 * LEADER_SETS)));
        uint32_t bip_set = lip_set + (LLC_SETS / 2);
        leader_flags[lip_set] = 1; // LIP leader
        leader_flags[bip_set] = 2; // BIP leader
    }
    psel = 512; // midpoint
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

    // RRIP: select block with max RRPV (3)
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
        rrpv[set][way] = 0;
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
        dead_bit[set][way] = 1; // Mark as reused
    } else {
        uint16_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
        dead_bit[set][way] = 0; // Mark as dead
    }

    // ---- Phase-adaptive DIP insertion depth selection ----
    uint8_t leader = leader_flags[set];
    bool use_lip = false;
    if (leader == 1) // LIP leader
        use_lip = true;
    else if (leader == 2) // BIP leader
        use_lip = false;
    else // follower sets
        use_lip = (psel < 512);

    // ---- Dead-block approximation: if >75% lines dead, prefer LIP insertion ----
    int dead_count = 0;
    for (uint32_t i = 0; i < LLC_WAYS; ++i)
        if (dead_bit[set][i] == 0) dead_count++;
    if (dead_count > (LLC_WAYS * 3) / 4)
        use_lip = true;

    // ---- DIP logic: LIP (always insert at RRPV=3), BIP (insert at RRPV=3 except 1/32 MRU) ----
    uint8_t insertion_rrpv = 3;
    if (!use_lip) {
        insertion_rrpv = ((rand() % 32) == 0) ? 0 : 3;
    }

    // ---- SHiP bias: high-reuse signature inserts at MRU (0) ----
    if (ship_table[ship_idx].reuse_counter >= 2)
        insertion_rrpv = 0;

    rrpv[set][way] = insertion_rrpv;
    line_sig[set][way] = sig;

    // ---- DIP set-dueling update ----
    // Only update PSEL for leader sets, on miss
    if (!hit) {
        if (leader == 1) { // LIP leader
            if (psel < 1023) psel++;
        }
        else if (leader == 2) { // BIP leader
            if (psel > 0) psel--;
        }
    }

    // ---- Periodic decay of SHiP reuse counters and dead bits ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
            if (ship_table[i].reuse_counter > 0)
                ship_table[i].reuse_counter--;
        // Decay dead bits to zero
        memset(dead_bit, 0, sizeof(dead_bit));
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int lip_sets = 0, bip_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i) {
        if (leader_flags[i] == 1) lip_sets++;
        else if (leader_flags[i] == 2) bip_sets++;
    }
    int dead_lines = 0;
    for (int s = 0; s < LLC_SETS; ++s)
        for (int w = 0; w < LLC_WAYS; ++w)
            if (dead_bit[s][w] == 0) dead_lines++;
    std::cout << "PASLH Policy: Phase-Adaptive SHiP-LIP Hybrid" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "LIP leader sets: " << lip_sets << ", BIP leader sets: " << bip_sets << std::endl;
    std::cout << "Dead lines (approx): " << dead_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Final PSEL: " << psel << " (0=LIP, 1023=BIP)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int dead_lines = 0;
    for (int s = 0; s < LLC_SETS; ++s)
        for (int w = 0; w < LLC_WAYS; ++w)
            if (dead_bit[s][w] == 0) dead_lines++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Dead lines (heartbeat): " << dead_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (heartbeat): " << psel << " (0=LIP, 1023=BIP)" << std::endl;
}