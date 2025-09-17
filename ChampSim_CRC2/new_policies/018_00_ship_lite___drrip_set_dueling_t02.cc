#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signature, 2-bit reuse counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating reuse counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DRRIP set-dueling: 10-bit PSEL, 64 leader sets for SRRIP, 64 for BRRIP ---
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // initialize to midpoint
#define NUM_LEADER_SETS 64
#define SRRIP_LEADER_SETS NUM_LEADER_SETS
#define BRRIP_LEADER_SETS NUM_LEADER_SETS
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant

    // Assign leader sets: interleave for fairness
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    for (uint32_t i = 0; i < SRRIP_LEADER_SETS; ++i)
        is_srrip_leader[i * (LLC_SETS / SRRIP_LEADER_SETS)] = 1;
    for (uint32_t i = 0; i < BRRIP_LEADER_SETS; ++i)
        is_brrip_leader[i * (LLC_SETS / BRRIP_LEADER_SETS) + LLC_SETS / (2 * BRRIP_LEADER_SETS)] = 1;
    PSEL = (1 << (PSEL_BITS - 1));
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
    // --- SHiP-lite signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: update SHiP-lite predictor, set RRPV=0 ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++; // mark as reused
        rrpv[set][way] = 0;
        return;
    }

    // --- DRRIP set-dueling: choose insertion policy ---
    uint8_t ins_rrpv = 3; // default distant
    bool use_srrip = false, use_brrip = false;
    if (is_srrip_leader[set]) use_srrip = true;
    else if (is_brrip_leader[set]) use_brrip = true;
    else use_srrip = (PSEL >= (1 << (PSEL_BITS - 1)));

    // --- SHiP-lite bias: if signature reused, insert at MRU ---
    if (ship_table[sig] >= 2) {
        ins_rrpv = 0;
    } else {
        // DRRIP: SRRIP inserts at 2, BRRIP inserts at 3 with low probability
        if (use_srrip) ins_rrpv = 2;
        else if (use_brrip) ins_rrpv = ((rand() % 32) == 0) ? 2 : 3; // BRRIP: 1/32 at 2, else 3
        else ins_rrpv = ((rand() % 32) == 0) ? 2 : 3; // follower sets use PSEL
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP-lite predictor for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ship_table[victim_sig] > 0) ship_table[victim_sig]--; // decay if evicted without reuse

    // --- Update PSEL for leader sets ---
    if (is_srrip_leader[set]) {
        if (hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++; // SRRIP leader hit: favor SRRIP
    } else if (is_brrip_leader[set]) {
        if (hit && PSEL > 0) PSEL--; // BRRIP leader hit: favor BRRIP
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + DRRIP Set-Dueling: Final statistics." << std::endl;
    uint32_t reused_cnt = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i] >= 2) reused_cnt++;
    std::cout << "SHiP-lite predictor: " << reused_cnt << " signatures predicted reused." << std::endl;
    std::cout << "Final PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL and reuse histogram
}