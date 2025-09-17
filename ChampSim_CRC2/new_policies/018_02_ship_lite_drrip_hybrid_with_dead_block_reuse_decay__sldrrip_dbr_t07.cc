#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// DRRIP: 10-bit PSEL selector, 64 leader sets
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // start neutral
#define NUM_LEADER_SETS 64
uint8_t leader_set_type[LLC_SETS]; // 0:SRRIP, 1:BRRIP, else follower

// SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature (256 entries)
#define SIG_BITS 6
#define SIG_TABLE_SIZE (1 << SIG_BITS)
uint8_t signature_table[SIG_TABLE_SIZE]; // 2 bits per entry

// Per-block metadata: PC signature and dead-block 2-bit reuse counter
uint8_t block_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block
uint8_t block_reuse_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// Helper: assign leader sets for SRRIP and BRRIP
void AssignLeaderSets() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        leader_set_type[s] = 2; // follower
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        leader_set_type[i] = 0; // SRRIP leader
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = 1; // BRRIP leader
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(signature_table, 1, sizeof(signature_table)); // start neutral
    memset(block_signature, 0, sizeof(block_signature));
    memset(block_reuse_ctr, 0, sizeof(block_reuse_ctr));
    AssignLeaderSets();
    PSEL = (1 << (PSEL_BITS - 1));
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
    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Standard RRIP victim search
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
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
    // --- SHiP-Lite Signature ---
    uint8_t pc_sig = champsim_crc2(PC, set) & (SIG_TABLE_SIZE-1);

    // --- On hit: promote to MRU, increment reuse counter ---
    if (hit) {
        rrpv[set][way] = 0;
        if (block_reuse_ctr[set][way] < 3)
            block_reuse_ctr[set][way]++;
        if (signature_table[block_signature[set][way]] < 3)
            signature_table[block_signature[set][way]]++;
        return;
    }

    // --- On miss/fill: decide insertion depth ---
    // Dead-block approximation: if block reuse counter==0, predicted dead
    uint8_t ins_rrpv = 2; // default SRRIP insertion
    if (block_reuse_ctr[set][way] == 0 || signature_table[pc_sig] == 0) {
        ins_rrpv = 3; // distant: dead or cold signature, minimize pollution
    } else {
        // DRRIP set-dueling
        if (leader_set_type[set] == 0) { // SRRIP leader
            ins_rrpv = 2;
        } else if (leader_set_type[set] == 1) { // BRRIP leader
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: 1/32 chance of SRRIP
        } else {
            // Follower: use PSEL to choose between SRRIP/BRRIP
            if (PSEL >= (1 << (PSEL_BITS - 1)))
                ins_rrpv = 2; // SRRIP
            else
                ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
        }
    }
    rrpv[set][way] = ins_rrpv;

    // Save PC signature for future reuse prediction
    block_signature[set][way] = pc_sig;
    block_reuse_ctr[set][way] = 0; // reset on fill

    // --- DRRIP PSEL update ---
    if (leader_set_type[set] == 0) { // SRRIP leader
        if (hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        if (hit && PSEL > 0) PSEL--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // SHiP signature counter histogram
    uint64_t sig_hist[4] = {0};
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_hist[signature_table[i]]++;
    std::cout << "SLDRRIP-DBR: Signature reuse histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << sig_hist[i] << " ";
    std::cout << std::endl;

    // PSEL value
    std::cout << "SLDRRIP-DBR: Final PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay of block reuse counters and signature table
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (block_reuse_ctr[s][w] > 0)
                block_reuse_ctr[s][w]--;

    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (signature_table[i] > 0)
            signature_table[i]--;
}