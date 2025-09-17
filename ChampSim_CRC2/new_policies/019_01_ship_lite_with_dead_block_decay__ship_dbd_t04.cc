#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-Lite: 6-bit PC signature per block, 2K-entry outcome table (2 bits per entry)
#define SIG_BITS 6
#define SIG_TABLE_SIZE 2048
uint8_t ship_table[SIG_TABLE_SIZE]; // 2-bit outcome per signature

// Per-block metadata: RRPV (2 bits), dead-counter (2 bits), signature (6 bits)
struct BlockMeta {
    uint8_t rrpv;        // 2 bits
    uint8_t dead_ctr;    // 2 bits
    uint8_t signature;   // 6 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Helper: extract 6-bit signature from PC
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 8) ^ (PC >> 16)) & ((1 << SIG_BITS) - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(ship_table, 1, sizeof(ship_table)); // Start neutral
}

// Find victim in the set (prefer dead blocks, else RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // 1. Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // 2. Prefer dead blocks (dead_ctr==0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (meta[set][way].dead_ctr == 0)
            return way;

    // 3. RRIP victim search
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
                meta[set][way].rrpv++;
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
    // --- Get signature ---
    uint8_t sig = GetSignature(PC);

    // --- On hit: promote to MRU, update SHiP table, reset dead-counter ---
    if (hit) {
        meta[set][way].rrpv = 0;
        meta[set][way].dead_ctr = 3; // Mark live
        // Reinforce signature as reused
        if (ship_table[sig] < 3) ship_table[sig]++;
        return;
    }

    // --- On miss/fill: choose insertion depth based on SHiP outcome ---
    uint8_t ins_rrpv = (ship_table[sig] >= 2) ? 0 : 3; // MRU if signature is "live", else distant
    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].dead_ctr = 3; // Assume live on fill
    meta[set][way].signature = sig;

    // --- On victim: update SHiP table for old block's signature ---
    if (victim_addr != 0) {
        uint8_t victim_sig = meta[set][way].signature;
        // If dead_ctr==0, block was not reused; penalize signature
        if (meta[set][way].dead_ctr == 0 && ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // SHiP table histogram
    uint64_t ship_hist[4] = {0};
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        ship_hist[ship_table[i]]++;
    std::cout << "SHiP-DBD: SHiP table histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age dead-counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].dead_ctr > 0)
                meta[s][w].dead_ctr--;
}