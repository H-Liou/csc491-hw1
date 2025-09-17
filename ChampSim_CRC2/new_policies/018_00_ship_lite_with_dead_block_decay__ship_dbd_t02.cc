#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (LLC_SETS * LLC_WAYS)
uint8_t ship_outcome[1 << SHIP_SIG_BITS]; // 64 entries, 2 bits each

// Per-block metadata: signature, 2-bit reuse counter, 2-bit RRPV
struct BlockMeta {
    uint8_t rrpv;         // 2 bits
    uint8_t reuse_ctr;    // 2 bits
    uint8_t ship_sig;     // 6 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Helper: extract 6-bit PC signature
inline uint8_t GetSignature(uint64_t PC) {
    // Use CRC or simple hash for mixing
    return champsim_crc2(PC, 0) & ((1 << SHIP_SIG_BITS) - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(ship_outcome, 1, sizeof(ship_outcome)); // neutral outcome
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            meta[s][w].rrpv = 3; // distant
            meta[s][w].reuse_ctr = 0;
            meta[s][w].ship_sig = 0;
        }
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
    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Standard RRIP victim search
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
    uint8_t sig = GetSignature(PC);

    // On hit: promote to MRU, increment reuse counter, update SHiP outcome
    if (hit) {
        meta[set][way].rrpv = 0;
        if (meta[set][way].reuse_ctr < 3)
            meta[set][way].reuse_ctr++;
        if (ship_outcome[sig] < 3)
            ship_outcome[sig]++;
        return;
    }

    // On miss/fill: set signature, reuse counter, insertion depth
    meta[set][way].ship_sig = sig;
    meta[set][way].reuse_ctr = 0;

    // Dead-block approximation: if victim's reuse_ctr == 0, decrement outcome
    uint8_t victim_sig = meta[set][way].ship_sig;
    if (meta[set][way].reuse_ctr == 0 && ship_outcome[victim_sig] > 0)
        ship_outcome[victim_sig]--;

    // SHiP-guided insertion: hot PC gets MRU, cold gets distant
    if (ship_outcome[sig] >= 2)
        meta[set][way].rrpv = 0; // MRU
    else
        meta[set][way].rrpv = 3; // distant

    // If previous block was dead (reuse_ctr==0), bias toward distant insertion
    if (meta[set][way].reuse_ctr == 0)
        meta[set][way].rrpv = 3;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Histogram of SHiP outcome counters
    uint64_t ship_hist[4] = {0};
    for (int i = 0; i < (1 << SHIP_SIG_BITS); ++i)
        ship_hist[ship_outcome[i]]++;
    std::cout << "SHiP-DBD: SHiP outcome histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << ship_hist[i] << " ";
    std::cout << std::endl;

    // Histogram of per-block reuse counters
    uint64_t reuse_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            reuse_hist[meta[s][w].reuse_ctr]++;
    std::cout << "SHiP-DBD: Block reuse histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << reuse_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age per-block reuse counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].reuse_ctr > 0)
                meta[s][w].reuse_ctr--;
}