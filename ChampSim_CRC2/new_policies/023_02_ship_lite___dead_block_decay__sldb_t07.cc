#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit PC signature, 2-bit outcome counter
#define SHIP_SIGNATURE_BITS 6
#define SHIP_SIGNATURES (1 << SHIP_SIGNATURE_BITS)
struct SHIPEntry {
    uint8_t ctr; // 2 bits
};
SHIPEntry ship_table[SHIP_SIGNATURES];

// Per-line metadata: 2 bits RRPV + 2 bits reuse counter + 6 bits PC signature
struct BlockMeta {
    uint8_t rrpv : 2;
    uint8_t reuse : 2;
    uint8_t sig  : 6;
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Periodic decay epoch (every 8192 accesses)
uint64_t access_counter = 0;
#define DECAY_EPOCH 8192

// Helper: compact signature hash from PC
inline uint8_t GetSignature(uint64_t PC) {
    // Simple CRC-based hash, 6 bits
    return champsim_crc2(PC) & (SHIP_SIGNATURES - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(meta, 0, sizeof(meta));
    access_counter = 0;
}

// Find victim in the set: prefer reuse==0 and RRPV==3, else RRPV==3, else increment RRPVs
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, try invalid
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Look for reuse==0 and RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (meta[set][way].rrpv == 3 && meta[set][way].reuse == 0)
            return way;

    // Next, any RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (meta[set][way].rrpv == 3)
            return way;

    // Else, increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (meta[set][way].rrpv < 3)
            meta[set][way].rrpv++;
    // Recursive call (should terminate quickly)
    return GetVictimInSet(cpu, set, current_set, PC, paddr, type);
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
    access_counter++;
    // --- Periodic decay of reuse counters ---
    if ((access_counter & (DECAY_EPOCH-1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (meta[s][w].reuse > 0)
                    meta[s][w].reuse--;
    }

    // --- Get PC signature ---
    uint8_t sig = GetSignature(PC);

    // --- On hit: promote to MRU and increase reuse ---
    if (hit) {
        meta[set][way].rrpv = 0;
        if (meta[set][way].reuse < 3) meta[set][way].reuse++;
        // Train SHiP: increment outcome counter for this signature
        if (ship_table[sig].ctr < 3) ship_table[sig].ctr++;
        return;
    }

    // --- On miss/fill: set insertion RRPV based on SHiP outcome ---
    meta[set][way].sig = sig;
    meta[set][way].reuse = 0;
    if (ship_table[sig].ctr >= 2)
        meta[set][way].rrpv = 0; // hot PC, insert at MRU (long retention)
    else
        meta[set][way].rrpv = 3; // cold PC, insert at LRU (short retention)

    // Train SHiP: decrement if line victimized with reuse==0
    if (victim_addr) {
        uint8_t vsig = meta[set][way].sig;
        if (meta[set][way].reuse == 0 && ship_table[vsig].ctr > 0)
            ship_table[vsig].ctr--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Count distribution of reuse counters and SHiP table
    uint32_t hot_pcs = 0;
    for (uint32_t i = 0; i < SHIP_SIGNATURES; ++i)
        if (ship_table[i].ctr >= 2) hot_pcs++;
    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].reuse == 0) dead_blocks++;
    std::cout << "SLDB: hot_pcs=" << hot_pcs << "/" << SHIP_SIGNATURES
              << ", dead_blocks=" << dead_blocks << "/" << (LLC_SETS*LLC_WAYS)
              << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed here (done inline)
}