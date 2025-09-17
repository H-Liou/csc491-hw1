#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 6-bit PC signature per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 6 bits/block

// SHiP-lite: 64-entry outcome table (indexed by signature)
uint8_t ship_table[64]; // 2 bits per entry

// Dead-block counter: 2 bits/block
uint8_t dbc[LLC_SETS][LLC_WAYS]; // 2 bits/block

// Bypass window per signature: 2 bits per entry (counts down)
uint8_t bypass_window[64]; // 2 bits per signature

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// Dead-block threshold and bypass window
const uint8_t DBC_THRESHOLD = 3;
const uint8_t BYPASS_WIN = 6; // cycles to bypass after dead block

// Helper: hash PC to 6 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

void InitReplacementState() {
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    memset(dbc, 0, sizeof(dbc));
    memset(bypass_window, 0, sizeof(bypass_window));
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Dead-block: prefer blocks with RRPV==RRIP_MAX
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    // If none, increment RRPV and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] < RRIP_MAX)
            rrpv[set][way]++;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    return 0;
}

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
    // --- SHiP-lite signature ---
    uint8_t sig = pc_hash(PC);

    // --- Dead-block counter update ---
    if (hit) {
        dbc[set][way] = 0; // reset on hit
    } else {
        if (dbc[set][way] < 3) dbc[set][way]++;
    }

    // --- Dead-block detection for bypass ---
    // If evicting a block with high DBC, set bypass window for its signature
    if (!hit && dbc[set][way] >= DBC_THRESHOLD) {
        bypass_window[pc_sig[set][way]] = BYPASS_WIN;
    }

    // --- SHiP outcome prediction for insertion ---
    uint8_t pred = ship_table[sig];
    uint8_t ins_rrpv = RRIP_MAX;

    // If bypass window is active, bypass insertion (do not cache)
    bool bypass_active = (bypass_window[sig] > 0);

    if (bypass_active) {
        // Do not insert into cache; set RRPV to max so it will be evicted soon
        ins_rrpv = RRIP_MAX;
    } else if (pred >= 2) {
        // If signature is frequently reused, insert at MRU
        ins_rrpv = RRIP_MRU;
    } else if (pred == 1) {
        // Weakly reused: insert at distant
        ins_rrpv = RRIP_DISTANT;
    } else {
        // Not reused: insert at LRU
        ins_rrpv = RRIP_MAX;
    }

    // --- Update RRIP and SHiP metadata ---
    if (hit) {
        rrpv[set][way] = RRIP_MRU;
        // Update SHiP outcome
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
    } else {
        // On insertion, set signature and RRPV
        pc_sig[set][way] = sig;
        rrpv[set][way] = ins_rrpv;
        // SHiP outcome: weak initial prediction
        if (ship_table[sig] > 0) ship_table[sig]--;
    }

    // --- Decay bypass window ---
    for (int i = 0; i < 64; ++i) {
        if (bypass_window[i] > 0)
            bypass_window[i]--;
    }

    // --- Periodic decay of DBC (every 4096 accesses) ---
    static uint64_t access_count = 0;
    access_count++;
    if ((access_count & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dbc[s][w] > 0) dbc[s][w]--;
    }
}

void PrintStats() {
    // Dead-block counters summary
    uint64_t high_dbc = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dbc[s][w] == 3)
                high_dbc++;
    std::cout << "HSDB: Blocks with high DBC: " << high_dbc << std::endl;

    // SHiP table summary
    std::cout << "HSDB: SHiP table (reuse counters): ";
    for (int i = 0; i < 64; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;

    // Bypass window summary
    uint64_t active_bypass = 0;
    for (int i = 0; i < 64; ++i)
        if (bypass_window[i] > 0)
            active_bypass++;
    std::cout << "HSDB: Active bypass windows: " << active_bypass << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print high DBC block count or active bypass windows
}