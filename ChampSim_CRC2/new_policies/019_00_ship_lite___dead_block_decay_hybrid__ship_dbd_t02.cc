#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 1024-entry, 2-bit outcome table
#define SHIP_TABLE_SIZE 1024
uint8_t ship_table[SHIP_TABLE_SIZE]; // 2 bits per entry

// Per-line: 2-bit dead-block (reuse) counter
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS];

// Per-line: 10-bit PC signature
uint16_t line_signature[LLC_SETS][LLC_WAYS];

// Heartbeat decay: track sets for periodic decay
uint32_t decay_ptr = 0;

// Helper: get SHiP index from PC signature
inline uint32_t GetSHIPIndex(uint64_t PC) {
    // Use lower 10 bits of CRC32 of PC for good mixing
    return champsim_crc32(PC) & (SHIP_TABLE_SIZE - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(ship_table, 1, sizeof(ship_table)); // neutral prediction
    memset(reuse_ctr, 0, sizeof(reuse_ctr));
    memset(line_signature, 0, sizeof(line_signature));
    decay_ptr = 0;
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

    // Dead-block approximation: prefer blocks with reuse_ctr==0
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (reuse_ctr[set][way] == 0)
            return way;

    // Otherwise, standard RRIP victim search (evict RRPV==3)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (current_set[way].valid && current_set[way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (current_set[way].rrpv < 3)
                current_set[way].rrpv++;
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
    // Get PC signature and SHiP index
    uint32_t ship_idx = GetSHIPIndex(PC);

    if (hit) {
        // On hit: promote to MRU, increment reuse counter, update SHiP
        reuse_ctr[set][way] = (reuse_ctr[set][way] < 3) ? reuse_ctr[set][way] + 1 : 3;
        ship_table[ship_idx] = (ship_table[ship_idx] < 3) ? ship_table[ship_idx] + 1 : 3;
        // Set RRPV to 0 (MRU)
        if (type == 0) // read
            ((BLOCK*)nullptr)[way].rrpv = 0; // Champsim will set rrpv externally
        return;
    }

    // On miss/fill: record signature
    line_signature[set][way] = ship_idx;

    // Use SHiP prediction to choose insertion depth
    uint8_t ins_rrpv = (ship_table[ship_idx] >= 2) ? 0 : 3; // 2/3: MRU, else distant

    // Insert with chosen RRPV
    ((BLOCK*)nullptr)[way].rrpv = ins_rrpv;

    // Reset reuse counter
    reuse_ctr[set][way] = 1; // start as possibly reusable

    // On victim: update SHiP table based on reuse counter
    uint16_t victim_sig = line_signature[set][way];
    if (reuse_ctr[set][way] == 0) {
        // Dead block: decrement SHiP outcome
        if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // SHiP table histogram
    uint64_t ship_hist[4] = {0};
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        ship_hist[ship_table[i]]++;
    std::cout << "SHIP-DBD: SHiP table histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodically decay reuse counters for a subset of sets
    for (int i = 0; i < 32; ++i) {
        uint32_t set = (decay_ptr + i) % LLC_SETS;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (reuse_ctr[set][way] > 0)
                reuse_ctr[set][way]--;
    }
    decay_ptr = (decay_ptr + 32) % LLC_SETS;
}