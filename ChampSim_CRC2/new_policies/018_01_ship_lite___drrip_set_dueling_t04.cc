#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-Lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating reuse counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- DRRIP: 2-bit RRPV per block, 10-bit PSEL, leader sets ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1)); // initialize to midpoint

// Leader set selection
#define NUM_LEADER_SETS 64
uint8_t leader_set_type[LLC_SETS]; // 0:SRRIP, 1:BRRIP, 2:Normal

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // distant
    memset(leader_set_type, 2, sizeof(leader_set_type)); // normal

    // Assign leader sets (even: SRRIP, odd: BRRIP)
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = (i * LLC_SETS) / NUM_LEADER_SETS;
        leader_set_type[set] = (i % 2 == 0) ? 0 : 1;
    }
}

// --- Find victim: standard SRRIP ---
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

    // --- On hit: update SHiP table, set RRPV=0 ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++; // mark as reused
        rrpv[set][way] = 0;
        return;
    }

    // --- On fill: determine insertion depth ---
    uint8_t ins_rrpv = 2; // default for DRRIP

    // Check leader set type
    if (leader_set_type[set] == 0) { // SRRIP leader
        ins_rrpv = 2;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: 1/32 at MRU, else distant
    } else {
        // Normal set: use PSEL to choose SRRIP or BRRIP
        if (psel >= (1 << (PSEL_BITS-1))) {
            ins_rrpv = 2; // SRRIP
        } else {
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
        }
    }

    // SHiP bias: if signature is "reused", insert at MRU
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP table for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ins_rrpv != 0 && ship_table[victim_sig] > 0)
        ship_table[victim_sig]--; // mark as not reused

    // --- DRRIP: update PSEL for leader sets ---
    if (leader_set_type[set] == 0) { // SRRIP leader
        // If hit, increment PSEL; else decrement
        if (hit && psel < ((1 << PSEL_BITS) - 1)) psel++;
        else if (!hit && psel > 0) psel--;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        if (hit && psel > 0) psel--;
        else if (!hit && psel < ((1 << PSEL_BITS) - 1)) psel++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + DRRIP: Final statistics." << std::endl;
    // Optionally print SHiP table histogram
    uint32_t reused_cnt = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i] >= 2) reused_cnt++;
    std::cout << "SHiP table: " << reused_cnt << " signatures predicted reused." << std::endl;
    std::cout << "Final PSEL: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print SHiP table stats
}