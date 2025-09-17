#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits/line
uint8_t reuse[LLC_SETS][LLC_WAYS];     // 2 bits/line: dead-block approximation

// --- DRRIP set-dueling ---
const uint32_t NUM_LEADER_SETS = 64;
uint8_t is_leader_sr[LLC_SETS];        // 1 if SRRIP leader, 0 otherwise
uint8_t is_leader_br[LLC_SETS];        // 1 if BRRIP leader, 0 otherwise
uint16_t leader_sr_sets[NUM_LEADER_SETS];
uint16_t leader_br_sets[NUM_LEADER_SETS];
uint16_t psel = 512;                   // 10-bit PSEL, neutral start

// --- Dead-block decay ---
uint64_t access_counter = 0;
const uint64_t DECAY_PERIOD = 100000;  // Decay every 100K accesses

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(reuse, 0, sizeof(reuse));

    // Pick leader sets for SRRIP and BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sr_sets[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
        leader_br_sets[i] = (LLC_SETS / NUM_LEADER_SETS) * i + LLC_SETS / (2 * NUM_LEADER_SETS);
    }
    memset(is_leader_sr, 0, sizeof(is_leader_sr));
    memset(is_leader_br, 0, sizeof(is_leader_br));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_sr[leader_sr_sets[i]] = 1;
        is_leader_br[leader_br_sets[i]] = 1;
    }
    psel = 512;
    access_counter = 0;
}

// --- Victim selection: SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
    }
}

// --- Replacement state update ---
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

    // --- Dead-block decay ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse[s][w] > 0) reuse[s][w]--;
    }

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // Promote to MRU
        if (reuse[set][way] < 3) reuse[set][way]++;
        return;
    }

    // --- DRRIP set-dueling: choose insertion policy ---
    bool use_sr = false, use_br = false;
    if (is_leader_sr[set]) use_sr = true;
    else if (is_leader_br[set]) use_br = true;
    else use_sr = (psel >= 512); // Majority: SRRIP if psel high, else BRRIP

    // --- Dead-block approximation: bias insertion ---
    // If reuse counter is low (<=1), treat as dead: insert at distant RRPV
    // If reuse counter is high (>=2), insert at MRU
    uint8_t ins_rrpv = 2; // default distant
    if (reuse[set][way] >= 2)
        ins_rrpv = 0; // MRU

    // DRRIP: override ins_rrpv for leader sets and set-dueling
    if (use_sr) ins_rrpv = 2; // SRRIP: always distant
    if (use_br) ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: mostly LRU, 1/32 distant

    rrpv[set][way] = ins_rrpv;
    reuse[set][way] = 0; // Reset reuse counter on fill

    // --- On eviction: update PSEL for leader sets ---
    if (victim_addr) {
        if (is_leader_sr[set]) {
            // If victim was reused before eviction, increment PSEL
            if (reuse[set][way] >= 2 && psel < 1023) psel++;
        }
        if (is_leader_br[set]) {
            // If victim was reused before eviction, decrement PSEL
            if (reuse[set][way] >= 2 && psel > 0) psel--;
        }
    }
}

// --- Stats ---
void PrintStats() {
    int dead_blocks = 0, live_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (reuse[s][w] <= 1) dead_blocks++;
            else live_blocks++;
    std::cout << "DRRIP-DBD: Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "DRRIP-DBD: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "DRRIP-DBD: PSEL: " << psel << std::endl;
}