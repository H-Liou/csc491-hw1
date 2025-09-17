#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
#define SHIP_BITS 2          // 2-bit outcome counter
#define SHIP_ENTRIES 8192    // 6-bit signature: PC % 8192
uint8_t SHIP_table[SHIP_ENTRIES]; // 16 KiB

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits per block
uint16_t ship_sig[LLC_SETS][LLC_WAYS];   // 13 bits per block (6b sig + 7b padding)

// --- Streaming detector per set ---
uint8_t stream_ctr[LLC_SETS];            // 2 bits per set: 0=not streaming, 3=strong streaming
uint64_t last_addr[LLC_SETS];            // last address seen per set

// Helper: compute compact PC signature
inline uint16_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 4)) & (SHIP_ENTRIES-1); // 6 bits
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));           // distant
    memset(ship_sig, 0, sizeof(ship_sig));   // signature
    memset(SHIP_table, 1, sizeof(SHIP_table)); // neutral SHiP prediction
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
}

// Find victim in the set (classic RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // RRIP scan
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
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
    // --- Streaming detector update ---
    uint64_t addr_delta = (last_addr[set] > 0) ? (paddr - last_addr[set]) : 0;
    last_addr[set] = paddr;
    if (addr_delta == 64 || addr_delta == -64) { // 64B line stride
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }

    // --- Compute PC signature ---
    uint16_t sig = GetSignature(PC);

    // --- On hit: mark as reusable ---
    if (hit) {
        rrpv[set][way] = 0; // protect
        SHIP_table[sig] = (SHIP_table[sig] < 3) ? (SHIP_table[sig]+1) : 3;
    }
    // --- On miss: control insertion ---
    else {
        ship_sig[set][way] = sig;
        if (stream_ctr[set] == 3) {
            // Streaming: always insert at RRPV=3 (distant), discourage reuse
            rrpv[set][way] = 3;
        } else {
            // SHIP-lite: insert at RRPV=0 if signature counter > 1, else RRPV=2
            if (SHIP_table[sig] > 1)
                rrpv[set][way] = 0;
            else
                rrpv[set][way] = 2;
        }
    }

    // --- On eviction: update SHiP table for the evicted block ---
    // If block was not reused (rrpv==3), decrement counter
    if (!hit && rrpv[set][way] == 3) {
        uint16_t victim_sig = ship_sig[set][way];
        if (SHIP_table[victim_sig] > 0)
            SHIP_table[victim_sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int protected_blocks = 0, distant_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    // SHiP table stats
    int high_reuse = 0, low_reuse = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i) {
        if (SHIP_table[i] > 1) high_reuse++;
        if (SHIP_table[i] == 0) low_reuse++;
    }
    std::cout << "SHiP-Lite with Streaming-Aware Insertion (SHiP-SA)" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "SHiP entries (high reuse): " << high_reuse << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "SHiP entries (low reuse): " << low_reuse << "/" << SHIP_ENTRIES << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int protected_blocks = 0, distant_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}