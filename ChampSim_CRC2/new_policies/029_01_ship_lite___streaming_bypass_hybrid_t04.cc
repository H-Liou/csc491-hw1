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
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_ENTRIES 64 // per set: 64 entries, 2 bits each = 128 bits/set
uint8_t ship_counter[LLC_SETS][SHIP_ENTRIES]; // 2 bits per entry

// Per-block: store signature for update
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// Streaming detector: per-set, 2-bit saturating counter, last address
uint64_t last_addr[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set
#define STREAM_THRESHOLD 3

// RRIP: 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Initialization ---
void InitReplacementState() {
    memset(ship_counter, 1, sizeof(ship_counter)); // Start at weak reuse
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // All blocks start as "long re-reference"
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Streaming detector update ---
inline void update_streaming(uint32_t set, uint64_t paddr) {
    uint64_t last = last_addr[set];
    uint64_t delta = (last == 0) ? 0 : (paddr > last ? paddr - last : last - paddr);
    // Detect monotonic stride: delta == block size (64B), or small stride
    if (last != 0 && (delta == 64 || delta == 128)) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_addr[set] = paddr;
}

// --- SHiP signature hash ---
inline uint8_t get_ship_sig(uint64_t PC) {
    // Simple CRC or mask for 6 bits
    return champsim_crc2(PC) & SHIP_SIG_MASK;
}

// --- Find victim: RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
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
    // Update streaming detector
    update_streaming(set, paddr);

    // --- Streaming bypass logic ---
    if (stream_ctr[set] >= STREAM_THRESHOLD) {
        // Streaming detected: bypass block (do not insert)
        rrpv[set][way] = 3; // Mark as long re-reference, likely to be replaced soon
        block_sig[set][way] = 0; // Clear signature
        return;
    }

    // --- SHiP-lite signature ---
    uint8_t sig = get_ship_sig(PC);
    block_sig[set][way] = sig;

    // --- Insertion depth: bias by SHiP outcome counter ---
    uint8_t counter = ship_counter[set][sig];
    uint8_t ins_rrpv = (counter >= 2) ? 1 : 3; // If strong reuse, insert shallow (RRPV=1), else distant (RRPV=3)

    if (hit) {
        rrpv[set][way] = 0; // Promote on hit
        // Update SHiP counter: increment for hit
        if (ship_counter[set][sig] < 3) ship_counter[set][sig]++;
    } else {
        rrpv[set][way] = ins_rrpv;
        // Update SHiP counter: decrement for miss (eviction or dead-on-arrival)
        if (ship_counter[set][sig] > 0) ship_counter[set][sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= STREAM_THRESHOLD)
            streaming_sets++;
    std::cout << "Sets with streaming detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    // Optionally print SHiP counter distribution
    uint64_t total_counters = 0, reused = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t i = 0; i < SHIP_ENTRIES; ++i) {
            total_counters++;
            if (ship_counter[s][i] >= 2) reused++;
        }
    std::cout << "SHiP signatures with strong reuse: " << reused << "/" << total_counters << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and SHiP reuse fraction
}