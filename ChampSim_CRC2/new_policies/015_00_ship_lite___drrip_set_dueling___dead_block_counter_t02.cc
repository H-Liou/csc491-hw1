#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 32 leader sets for SRRIP, 32 for BRRIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_srrip[LLC_SETS];
bool is_leader_brrip[LLC_SETS];

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- Dead-block counter: 2 bits per block ---
uint8_t dead_counter[LLC_SETS][LLC_WAYS]; // 2-bit saturating counter

// --- Periodic decay ---
#define DEAD_DECAY_INTERVAL 4096
uint64_t fill_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant
    memset(dead_counter, 0, sizeof(dead_counter));
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

// --- Find victim: prefer dead blocks, else SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, try to find a block with dead_counter == 3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_counter[set][way] == 3)
            return way;
    // Otherwise, standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
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

    // --- On hit: update SHiP outcome, set RRPV=0, reset dead counter ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = 0;
        dead_counter[set][way] = 0;
        // Set-dueling update
        if (is_leader_srrip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_brrip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- DRRIP policy selection: SRRIP or BRRIP ---
    bool use_srrip = false;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_brrip[set])
        use_srrip = false;
    else
        use_srrip = (PSEL >= 512);

    // --- Decide insertion RRPV ---
    uint8_t ins_rrpv = 2; // SRRIP default
    if (!use_srrip) {
        // BRRIP: insert at RRPV=3 with low probability (1/32), else RRPV=2
        ins_rrpv = ((rand() % 32) == 0) ? 3 : 2;
    }

    // --- SHiP outcome: for high-reuse sigs, insert at MRU ---
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;
    dead_counter[set][way] = 0;

    // --- On eviction: update SHiP outcome for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ins_rrpv == 3 && ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;

    // --- Dead-block counter update: increment on miss for all non-hit blocks ---
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
    std::cout << "SHiP-Lite + DRRIP Set-Dueling + Dead-Block Counter: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, SHiP histogram, dead-block stats
}