#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
uint16_t psel = 512; // 10 bits, mid value
uint8_t is_leader_lip[LLC_SETS]; // 1 if LIP leader, 2 if BIP leader, 0 otherwise

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter table (4096 entries)
#define SIG_BITS 6
#define SIG_TABLE_SIZE 4096
uint8_t ship_ctr[SIG_TABLE_SIZE]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- Dead-block predictor: 2-bit counter per block, periodic decay
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Selective bypass: if dead_ctr[set][way] >= 2 for all ways, bypass insertions in this set
uint8_t set_dead_bypass[LLC_SETS]; // 1 if set is in bypass mode

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(ship_ctr, 1, sizeof(ship_ctr)); // neutral initial value
    memset(block_sig, 0, sizeof(block_sig));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(set_dead_bypass, 0, sizeof(set_dead_bypass));
    memset(is_leader_lip, 0, sizeof(is_leader_lip));
    // Assign leader sets for LIP and BIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_lip[i] = 1; // first 64: LIP
        is_leader_lip[LLC_SETS - 1 - i] = 2; // last 64: BIP
    }
    psel = 512;
}

//--------------------------------------------
// Find victim in the set (LRU order)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // If set is in bypass mode, do not insert (simulate by returning LLC_WAYS)
    if (set_dead_bypass[set])
        return LLC_WAYS;

    // Standard LRU victim selection (lowest dead_ctr first, then lowest way index)
    uint32_t victim = 0;
    uint8_t min_dead = dead_ctr[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (dead_ctr[set][way] < min_dead) {
            min_dead = dead_ctr[set][way];
            victim = way;
        }
    }
    return victim;
}

//--------------------------------------------
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
    // --- Dead-block predictor decay: every 4096 accesses, decay all counters by 1
    static uint64_t global_access = 0;
    global_access++;
    if ((global_access & 0xFFF) == 0) { // every 4096 accesses
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }

    // --- SHiP-lite signature ---
    uint16_t sig = (PC ^ (PC >> 6)) & ((1 << SIG_BITS) - 1); // 6-bit signature
    uint16_t sig_idx = sig ^ (set & 0xFFF); // index into ship_ctr table

    // --- DIP set-dueling ---
    bool use_lip = false;
    if (is_leader_lip[set] == 1) use_lip = true;
    else if (is_leader_lip[set] == 2) use_lip = false;
    else use_lip = (psel >= 512);

    // --- On hit ---
    if (hit) {
        // Reset dead-block counter
        dead_ctr[set][way] = 0;
        // Update SHiP outcome counter (increment, max 3)
        if (ship_ctr[sig_idx] < 3) ship_ctr[sig_idx]++;
    } else {
        // --- On miss: insertion depth ---
        block_sig[set][way] = sig;
        // Use SHiP outcome to bias insertion
        if (ship_ctr[sig_idx] >= 2) {
            // Proven reusable: insert at MRU
            // (LIP: insert at LRU, BIP: insert at MRU with 1/32 probability)
            dead_ctr[set][way] = 0;
        } else {
            // Use DIP: LIP (insert at LRU) or BIP (insert at MRU with 1/32 probability)
            if (use_lip) {
                dead_ctr[set][way] = 2; // treat as less likely to be reused
            } else {
                dead_ctr[set][way] = (rand() % 32 == 0) ? 0 : 2;
            }
        }
    }

    // --- DIP set-dueling PSEL update ---
    if (!hit && (is_leader_lip[set] == 1)) {
        if (hit) { if (psel < 1023) psel++; }
        else { if (psel > 0) psel--; }
    }
    if (!hit && (is_leader_lip[set] == 2)) {
        if (hit) { if (psel > 0) psel--; }
        else { if (psel < 1023) psel++; }
    }

    // --- On eviction: update SHiP and dead-block outcome counter ---
    if (!hit && way < LLC_WAYS) {
        uint8_t evicted_sig = block_sig[set][way];
        uint16_t evict_idx = evicted_sig ^ (set & 0xFFF);
        // If block was not reused (dead_ctr==2), decrement outcome counter
        if (dead_ctr[set][way] == 2 && ship_ctr[evict_idx] > 0)
            ship_ctr[evict_idx]--;
        // Increment dead-block counter for evicted block
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // --- Selective bypass: if all ways in set have dead_ctr >= 2, enable bypass
    uint8_t all_dead = 1;
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        if (dead_ctr[set][w] < 2) { all_dead = 0; break; }
    set_dead_bypass[set] = all_dead;
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Dead-Block Prediction + Selective Bypass: Final statistics." << std::endl;
    uint32_t bypass_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (set_dead_bypass[s]) bypass_sets++;
    std::cout << "Bypass sets at end: " << bypass_sets << " / " << LLC_SETS << std::endl;
    std::cout << "Final PSEL: " << psel << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[Heartbeat] Bypass sets: ";
    uint32_t bypass_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (set_dead_bypass[s]) bypass_sets++;
    std::cout << bypass_sets << " | PSEL: " << psel << std::endl;
}