#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP-style set-dueling: 32 leader sets for LIP, 32 for BIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 entries
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2-bit saturating counter per signature
uint8_t block_sig[LLC_SETS][LLC_WAYS];  // 6-bit signature per block

// --- Dead-block approximation: 2-bit per-line counter, periodic decay ---
uint8_t dead_counter[LLC_SETS][LLC_WAYS]; // 2 bits per block
#define DEAD_DECAY_INTERVAL 4096
uint64_t fill_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(ship_outcome, 0, sizeof(ship_outcome));
    memset(block_sig, 0, sizeof(block_sig));
    memset(dead_counter, 0, sizeof(dead_counter));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_lip[s] = true, is_leader_bip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_lip[s] = false, is_leader_bip[s] = true;
        else
            is_leader_lip[s] = false, is_leader_bip[s] = false;
    }
    PSEL = 512;
    fill_count = 0;
}

// --- Find victim: prefer blocks with dead_counter==3, else LRU ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_counter[set][way] == 3)
            return way;
    // Otherwise, pick LRU (lowest ship_outcome, then lowest dead_counter)
    uint32_t victim = 0;
    uint8_t min_outcome = ship_outcome[block_sig[set][0]];
    uint8_t min_dead = dead_counter[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        uint8_t outcome = ship_outcome[block_sig[set][way]];
        if (outcome < min_outcome ||
            (outcome == min_outcome && dead_counter[set][way] < min_dead)) {
            victim = way;
            min_outcome = outcome;
            min_dead = dead_counter[set][way];
        }
    }
    return victim;
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

    // --- On hit: update SHiP outcome, reset dead counter ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
        dead_counter[set][way] = 0; // reset dead counter on reuse

        // DIP set-dueling update
        if (is_leader_lip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_bip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- On fill: choose insertion policy ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL >= 512);

    uint8_t ins_pos = LLC_WAYS - 1; // default LRU position
    if (use_lip) {
        ins_pos = 0; // LIP: insert at MRU
    } else {
        // BIP: insert at MRU only 1/32 fills
        ins_pos = ((rand() % 32) == 0) ? 0 : (LLC_WAYS - 1);
    }

    // SHiP bias: if outcome counter for sig is high, insert at MRU; if low, at LRU
    if (ship_outcome[sig] >= 2)
        ins_pos = 0;
    else if (ship_outcome[sig] == 0)
        ins_pos = LLC_WAYS - 1;

    block_sig[set][way] = sig;
    dead_counter[set][way] = 0; // reset on fill

    // --- On eviction: update SHiP outcome counter for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    // If block was not reused (dead_counter==3), decrement outcome counter
    if (dead_counter[set][way] == 3 && ship_outcome[victim_sig] > 0)
        ship_outcome[victim_sig]++;

    // --- Dead-block counter: increment for blocks not hit ---
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (w != way && dead_counter[set][w] < 3)
            dead_counter[set][w]++;
    }

    // --- Periodic decay of dead-block counters ---
    fill_count++;
    if ((fill_count % DEAD_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_counter[s][w] > 0)
                    dead_counter[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-LIP Hybrid with Dead-Block Decay: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
    // Optionally print SHiP outcome histogram
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print SHiP outcome histogram, PSEL
}