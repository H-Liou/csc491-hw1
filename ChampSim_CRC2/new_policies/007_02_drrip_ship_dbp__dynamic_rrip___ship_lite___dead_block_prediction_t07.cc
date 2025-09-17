#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

// --- Parameters ---
#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP set-dueling ---
#define DRRIP_LEADER_SETS 32
#define DRRIP_PSEL_MAX 1023 // 10 bits

// --- SHiP-lite ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 per set
uint8_t ship_sig[LLC_SETS][SHIP_SIG_ENTRIES]; // 2 bits per signature

// --- RRIP ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits/line

// --- Dead-block predictor ---
uint8_t dead_count[LLC_SETS][LLC_WAYS];  // 2 bits/line, periodic decay

// --- DRRIP metadata ---
uint16_t psel = DRRIP_PSEL_MAX / 2;      // 10-bit PSEL
bool is_srrip_leader[LLC_SETS];
bool is_brrip_leader[LLC_SETS];

// --- Leader set assignment ---
void InitLeaderSets() {
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    for (uint32_t k = 0; k < DRRIP_LEADER_SETS; ++k) {
        is_srrip_leader[k] = true;
        is_brrip_leader[LLC_SETS - 1 - k] = true;
    }
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU on cold start
    memset(ship_sig, 1, sizeof(ship_sig)); // Neutral SHiP counters
    memset(dead_count, 1, sizeof(dead_count)); // Neutral dead-block
    InitLeaderSets();
    psel = DRRIP_PSEL_MAX / 2;
}

// --- Find victim: prefer dead blocks, else RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks (dead_count == 0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_count[set][way] == 0)
            return way;
    }
    // Otherwise, standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
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
    // --- SHiP signature: 6 bits from PC ---
    uint32_t sig = (PC ^ (PC >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- DRRIP insertion policy selection ---
    bool use_srrip = false;
    if (is_srrip_leader[set])
        use_srrip = true;
    else if (is_brrip_leader[set])
        use_srrip = false;
    else
        use_srrip = (psel >= DRRIP_PSEL_MAX / 2);

    // --- Dead-block predictor decay (every 1024 fills) ---
    static uint64_t global_fill_ctr = 0;
    global_fill_ctr++;
    if ((global_fill_ctr & 0x3FF) == 0) { // Every 1024 fills
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_count[s][w] > 0) dead_count[s][w]--;
    }

    // --- On cache hit ---
    if (hit) {
        // Promote to MRU
        rrpv[set][way] = 0;
        // SHiP: reward signature
        if (ship_sig[set][sig] < 3) ship_sig[set][sig]++;
        // Dead-block predictor: strong reuse
        dead_count[set][way] = 3;
    } else {
        // --- On fill ---
        // SHiP-guided insertion
        if (ship_sig[set][sig] >= 2) {
            rrpv[set][way] = 0; // MRU (likely reused)
        } else {
            // DRRIP: SRRIP (MRU) or BRRIP (mostly distant)
            if (use_srrip) {
                rrpv[set][way] = 2;
            } else {
                rrpv[set][way] = (rand() % 32 == 0) ? 0 : 2; // BRRIP: MRU 1/32, else 2
            }
        }
        // Dead-block predictor: newly filled block, weakly alive
        dead_count[set][way] = 1;

        // SHiP: weakly not reused if miss
        if (ship_sig[set][sig] > 0) ship_sig[set][sig]--;
    }

    // --- DRRIP set-dueling feedback ---
    if (is_srrip_leader[set]) {
        if (hit && rrpv[set][way] == 0 && !use_srrip && ship_sig[set][sig] < 2)
            if (psel < DRRIP_PSEL_MAX) psel++;
    } else if (is_brrip_leader[set]) {
        if (hit && rrpv[set][way] == 0 && use_srrip && ship_sig[set][sig] < 2)
            if (psel > 0) psel--;
    }
}

// --- Stats ---
void PrintStats() {
    int ship_reused = 0, ship_total = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
            if (ship_sig[s][i] >= 2) ship_reused++;
            ship_total++;
        }
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_count[s][w] == 0) dead_blocks++;
    }
    std::cout << "DRRIP-SHiP-DBP: SHiP reused sigs: " << ship_reused << " / " << ship_total << std::endl;
    std::cout << "DRRIP-SHiP-DBP: Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "DRRIP-SHiP-DBP: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_count[s][w] == 0) dead_blocks++;
    std::cout << "DRRIP-SHiP-DBP: Dead blocks: " << dead_blocks << std::endl;
    std::cout << "DRRIP-SHiP-DBP: PSEL: " << psel << std::endl;
}