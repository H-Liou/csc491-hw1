#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata: per-set signature table ---
#define SIG_BITS 6
#define SIG_ENTRIES 8        // per set: 8 entries
#define SIG_MASK ((1 << SIG_BITS) - 1)
struct SHIPEntry {
    uint16_t sig;            // 6 bits
    uint8_t reuse_ctr;       // 2 bits
};
SHIPEntry ship_table[LLC_SETS][SIG_ENTRIES];

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits per block
uint16_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block: last fill signature

// --- Streaming detector per set ---
uint8_t stream_ctr[LLC_SETS];        // 2 bits per set: 0=not streaming, 3=strong streaming
uint64_t last_addr[LLC_SETS];        // last address seen per set

// Helper: compute PC signature
inline uint16_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 3)) & SIG_MASK;
}

// Helper: find or allocate entry in SHiP table
SHIPEntry* FindSHIPEntry(uint32_t set, uint16_t sig) {
    for (int i = 0; i < SIG_ENTRIES; ++i)
        if (ship_table[set][i].sig == sig)
            return &ship_table[set][i];
    // Not found: allocate (LRU replacement)
    static uint64_t lru_tick[LLC_SETS][SIG_ENTRIES] = {{0}};
    uint64_t min_tick = lru_tick[set][0];
    int min_idx = 0;
    for (int i = 1; i < SIG_ENTRIES; ++i) {
        if (lru_tick[set][i] < min_tick) {
            min_tick = lru_tick[set][i];
            min_idx = i;
        }
    }
    ship_table[set][min_idx].sig = sig;
    ship_table[set][min_idx].reuse_ctr = 1; // initialize to weak reuse
    lru_tick[set][min_idx] = min_tick + 1;
    return &ship_table[set][min_idx];
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));         // distant
    memset(block_sig, 0, sizeof(block_sig));
    memset(ship_table, 0, sizeof(ship_table));
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
    // Classic RRIP scan
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

    // --- SHiP-lite signature ---
    uint16_t sig = GetSignature(PC);
    SHIPEntry* entry = FindSHIPEntry(set, sig);

    // --- On hit: update reuse counter for signature, protect block ---
    if (hit) {
        if (entry->reuse_ctr < 3) entry->reuse_ctr++;
        rrpv[set][way] = 0; // protect
    }
    // --- On miss: control insertion ---
    else {
        block_sig[set][way] = sig;
        // Streaming detected: bypass (simulate by not inserting, i.e., set valid=0 if allowed)
        if (stream_ctr[set] == 3) {
            rrpv[set][way] = 3; // insert at distant RRPV (or bypass if infra allows)
        } else {
            // Signature-based insertion: high reuse => protect, else distant
            if (entry->reuse_ctr >= 2)
                rrpv[set][way] = 0; // insert as protected
            else
                rrpv[set][way] = 3; // insert at distant
        }
    }

    // --- On eviction: update SHiP outcome counter ---
    if (!hit) {
        // If victim block had signature, update its reuse counter
        uint16_t victim_sig = block_sig[set][way];
        SHIPEntry* victim_entry = FindSHIPEntry(set, victim_sig);
        // If block was not reused before eviction, decrement reuse counter
        if (rrpv[set][way] == 3 && victim_entry->reuse_ctr > 0)
            victim_entry->reuse_ctr--;
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
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    // Print SHiP table reuse counters summary
    int high_reuse = 0, low_reuse = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (int i = 0; i < SIG_ENTRIES; ++i)
            if (ship_table[set][i].reuse_ctr >= 2) high_reuse++;
            else low_reuse++;
    std::cout << "High-reuse SHiP entries: " << high_reuse << std::endl;
    std::cout << "Low-reuse SHiP entries: " << low_reuse << std::endl;
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