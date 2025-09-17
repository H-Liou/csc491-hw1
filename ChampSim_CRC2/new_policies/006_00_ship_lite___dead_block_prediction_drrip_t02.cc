#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DRRIP set-dueling: 32 leader sets for SRRIP, 32 for BRRIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_srrip[LLC_SETS];
bool is_leader_brrip[LLC_SETS];

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 entries
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2-bit saturating counter per signature
uint8_t block_sig[LLC_SETS][LLC_WAYS];  // 6-bit signature per block

// --- Dead-block predictor: 2-bit reuse counter per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2-bit counter per block

// --- Periodic decay parameters ---
#define DEAD_DECAY_INTERVAL 4096 // Decay every 4096 fills
uint64_t fill_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // all blocks start distant
    memset(ship_outcome, 0, sizeof(ship_outcome));
    memset(block_sig, 0, sizeof(block_sig));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_srrip[s] = true, is_leader_brrip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_srrip[s] = false, is_leader_brrip[s] = true;
        else
            is_leader_srrip[s] = false, is_leader_brrip[s] = false;
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
    // RRIP victim selection: pick block with RRPV==3, else increment all and retry
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

    // --- On hit: set RRPV to 0, update SHiP outcome, update dead-block counter ---
    if (hit) {
        rrpv[set][way] = 0;
        block_sig[set][way] = sig;
        // Update SHiP outcome counter (max 3)
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
        // Dead-block predictor: increment reuse counter (max 3)
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        // DRRIP set-dueling update
        if (is_leader_srrip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_brrip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- On fill: choose insertion policy ---
    bool use_srrip = false;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_brrip[set])
        use_srrip = false;
    else
        use_srrip = (PSEL >= 512);

    uint8_t ins_rrpv = 2; // Default SRRIP: insert at 2
    if (!use_srrip) {
        // BRRIP: insert at 3 except 1/32 fills at 2
        ins_rrpv = ((rand() % 32) == 0) ? 2 : 3;
    }
    // SHiP bias: if outcome counter for sig is high, insert at 0 (long reuse); if low, at 3 (dead)
    if (ship_outcome[sig] >= 2)
        ins_rrpv = 0;
    else if (ship_outcome[sig] == 0)
        ins_rrpv = 3;

    // Dead-block predictor: if block predicted dead (dead_ctr==0), force distant insertion
    if (dead_ctr[set][way] == 0)
        ins_rrpv = 3;

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;
    dead_ctr[set][way] = 0; // reset reuse counter on fill

    // --- On eviction: update SHiP outcome counter for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    // If block was not reused (RRPV==3 at eviction), decrement outcome counter
    if (rrpv[set][way] == 3 && ship_outcome[victim_sig] > 0)
        ship_outcome[victim_sig]--;

    // --- Periodic decay of dead-block counters ---
    fill_count++;
    if ((fill_count % DEAD_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Dead-Block Prediction DRRIP: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
    // Optionally print SHiP outcome histogram
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print SHiP outcome histogram, PSEL
}