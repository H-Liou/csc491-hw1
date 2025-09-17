#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-Block Predictor: 2-bit reuse counter per block ---
uint8_t dbp[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2-bit per signature
uint8_t block_sig[LLC_SETS][LLC_WAYS];  // 6-bit per block

// --- DIP-style set-dueling: 32 leader sets per policy, 10-bit PSEL ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit selector
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- Dead-block decay interval ---
#define DBP_DECAY_INTERVAL 4096
uint64_t fill_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dbp, 0, sizeof(dbp));
    memset(ship_outcome, 0, sizeof(ship_outcome));
    memset(block_sig, 0, sizeof(block_sig));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        is_leader_lip[s] = (s < NUM_LEADER_SETS);
        is_leader_bip[s] = (s >= LLC_SETS - NUM_LEADER_SETS);
    }
    PSEL = 512;
    fill_count = 0;
}

// --- Find victim: RRIP victim selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Dead-block predictor: prefer evicting blocks with dbp==0 (dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dbp[set][way] == 0)
            return way;
    // If none dead, standard RRIP: pick block with RRPV==3, else increment all and retry
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
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
    // --- SHiP signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: ---
    if (hit) {
        rrpv[set][way] = 0;
        block_sig[set][way] = sig;
        // Increment SHiP outcome counter (max 3)
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
        // Update DBP: increase reuse counter (max 3)
        if (dbp[set][way] < 3) dbp[set][way]++;
        // DIP set-dueling update
        if (is_leader_lip[set] && PSEL > 0) PSEL--;
        if (is_leader_bip[set] && PSEL < 1023) PSEL++;
        return;
    }

    // --- On fill: ---
    bool use_lip = false;
    if (is_leader_lip[set]) use_lip = true;
    else if (is_leader_bip[set]) use_lip = false;
    else use_lip = (PSEL < 512);

    // Dead-block prediction: if recent victim's dbp==0, streaming detected—bypass (insert at distant RRPV)
    uint8_t ins_rrpv = 2; // Default
    if (dbp[set][way] == 0)
        ins_rrpv = 3; // Bypass

    // SHiP bias: if outcome counter for sig is high, favor MRU (insert at 0)
    if (ship_outcome[sig] >= 2)
        ins_rrpv = 0;
    else if (ship_outcome[sig] == 0)
        ins_rrpv = 3;

    // DIP insertion policy
    if (use_lip)
        ins_rrpv = 3; // LIP: always LRU
    else { // BIP: MRU except 1/32 at LRU
        if ((rand() % 32) == 0)
            ins_rrpv = 3;
        else if (ins_rrpv > 0)
            ins_rrpv = 0;
    }

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;
    dbp[set][way] = 1; // On fill, set reuse counter to 1

    // --- On eviction: update SHiP and DBP for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    // If block was not reused (RRPV==3 at eviction), decrement outcome counter
    if (rrpv[set][way] == 3 && ship_outcome[victim_sig] > 0)
        ship_outcome[victim_sig]--;
    // Dead-block predictor: if block evicted at RRPV==3, decay reuse counter
    if (rrpv[set][way] == 3 && dbp[set][way] > 0)
        dbp[set][way]--;

    // --- Periodic decay of DBP counters to catch phase changes ---
    fill_count++;
    if ((fill_count % DBP_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dbp[s][w] > 0) dbp[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Phase-Aware Dead-Block SHiP DIP: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print SHiP outcome histogram, PSEL
}