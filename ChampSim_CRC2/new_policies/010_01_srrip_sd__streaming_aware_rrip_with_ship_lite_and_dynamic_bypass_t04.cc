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
uint8_t pc_sig[LLC_SETS][LLC_WAYS];      // 6 bits/block

// SHiP-lite: 64-entry outcome table (indexed by signature), 2 bits/entry
uint8_t ship_table[64]; // 2 bits per entry

// Streaming Detector: 2-bit counter per set
uint8_t streaming_counter[LLC_SETS]; // 2 bits/set

// Streaming Detector: last address per set
uint64_t last_addr[LLC_SETS];

// Streaming Detector: last delta per set
int64_t last_delta[LLC_SETS];

// Helper: hash PC to 6 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    memset(streaming_counter, 0, sizeof(streaming_counter));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
}

// Find victim in the set
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
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
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
    // --- Streaming Detector ---
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    bool monotonic = (last_delta[set] != 0) && (delta == last_delta[set]);
    if (monotonic)
    {
        if (streaming_counter[set] < 3) streaming_counter[set]++;
    }
    else
    {
        if (streaming_counter[set] > 0) streaming_counter[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- SHiP-lite signature ---
    uint8_t sig = pc_hash(PC);

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Update SHiP outcome
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
        return;
    }

    // --- On cache miss or fill ---
    uint8_t ins_rrpv = 2; // Default SRRIP insertion depth

    // Streaming detected: bypass (do not insert) or insert at distant RRPV
    if (streaming_counter[set] == 3) {
        ins_rrpv = 3; // Insert at LRU (distant), equivalent to bypassing quickly
    }

    // SHiP bias: if PC signature is frequently reused, insert at MRU
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;

    // Update block metadata
    pc_sig[set][way] = sig;
    rrpv[set][way] = ins_rrpv;

    // SHiP outcome: weak initial prediction
    if (ship_table[sig] > 0) ship_table[sig]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_counter[s] == 3)
            streaming_sets++;
    std::cout << "SRRIP-SD: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // SHiP table summary
    std::cout << "SRRIP-SD: SHiP table (reuse counters): ";
    for (int i = 0; i < 64; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set ratio
}