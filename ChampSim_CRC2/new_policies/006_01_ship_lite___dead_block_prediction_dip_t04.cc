#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP set-dueling: 32 leader sets for LIP, 32 for BIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 entries
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2-bit saturating counter per signature
uint8_t block_sig[LLC_SETS][LLC_WAYS];  // 6-bit signature per block

// --- Dead-block predictor: 2-bit reuse counter per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2-bit per block

// --- Periodic decay (every 100K accesses) ---
uint64_t access_count = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(ship_outcome, 0, sizeof(ship_outcome));
    memset(block_sig, 0, sizeof(block_sig));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_lip[s] = true, is_leader_bip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_lip[s] = false, is_leader_bip[s] = true;
        else
            is_leader_lip[s] = false, is_leader_bip[s] = false;
    }
    PSEL = 512;
    access_count = 0;
}

// Find victim in the set: LRU among blocks with dead_ctr == 0, else normal LRU
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer to evict blocks predicted dead (dead_ctr == 0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_ctr[set][way] == 0)
            return way;
    }
    // If none predicted dead, evict LRU (lowest dead_ctr value)
    uint32_t victim = 0;
    uint8_t min_ctr = dead_ctr[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (dead_ctr[set][way] < min_ctr) {
            min_ctr = dead_ctr[set][way];
            victim = way;
        }
    }
    return victim;
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
    access_count++;

    // --- SHiP signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: increment dead_ctr, update SHiP outcome ---
    if (hit) {
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        block_sig[set][way] = sig;
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
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

    // SHiP bias: if outcome counter for sig is high, insert as BIP (minimal promotion)
    bool ship_long_reuse = (ship_outcome[sig] >= 2);

    // Dead-block bias: if predicted dead, insert as LIP (most distant)
    bool predicted_dead = (dead_ctr[set][way] == 0);

    // Insertion logic:
    // - If predicted dead OR use_lip, insert as LIP (dead: at tail, minimal promotion)
    // - If SHiP predicts reuse OR use_bip, insert as BIP (insert at tail, but promote on 1/32 fills)
    bool insert_at_tail = true;
    bool promote = false;
    if (predicted_dead || use_lip) {
        insert_at_tail = true;
        promote = false;
    } else if (ship_long_reuse || !use_lip) {
        insert_at_tail = true;
        promote = ((rand() % 32) == 0);
    }

    // On fill: reset dead_ctr, set block_sig
    dead_ctr[set][way] = promote ? 1 : 0;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP outcome counter for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    // If block was not reused (dead_ctr==0 at eviction), decrement outcome counter
    if (dead_ctr[set][way] == 0 && ship_outcome[victim_sig] > 0)
        ship_outcome[victim_sig]--;

    // --- Periodic decay of dead_ctr ---
    if (access_count % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Dead-Block Prediction DIP: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
    // Optionally print SHiP outcome histogram
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print SHiP outcome histogram, PSEL
}