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
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_counter[SHIP_TABLE_SIZE]; // 2 bits per entry

// Per-block signature storage
uint8_t block_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block

// RRIP: 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// Streaming detector: Per-set, 2-bit saturating counter, last address
uint64_t last_addr[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

#define STREAM_THRESHOLD 3

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_counter, 1, sizeof(ship_counter)); // neutral start
    memset(block_signature, 0, sizeof(block_signature));
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

// --- Find victim: RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming detected: bypass insertion (no victim needed)
    if (stream_ctr[set] >= STREAM_THRESHOLD)
        return LLC_WAYS; // special value: bypass

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

    // Compute PC signature
    uint8_t sig = champsim_crc2(PC) & SHIP_SIG_MASK;

    // Streaming detected: bypass insertion
    if (stream_ctr[set] >= STREAM_THRESHOLD) {
        // Do not insert block, no metadata update needed
        return;
    }

    // On hit: promote block and increment SHiP counter
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_counter[block_signature[set][way]] < 3)
            ship_counter[block_signature[set][way]]++;
    } else {
        // On miss: set block signature
        block_signature[set][way] = sig;

        // SHiP-lite: use counter to select insertion depth
        uint8_t ins_rrpv = (ship_counter[sig] >= 2) ? 2 : 3; // 2: keep, 3: evict soon
        rrpv[set][way] = ins_rrpv;
    }

    // On eviction: decrement SHiP counter if block was not reused
    if (!hit && way < LLC_WAYS) {
        uint8_t evict_sig = block_signature[set][way];
        if (ship_counter[evict_sig] > 0)
            ship_counter[evict_sig]--;
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
    uint32_t high_reuse = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_counter[i] >= 2)
            high_reuse++;
    std::cout << "High-reuse PC signatures: " << high_reuse << "/" << SHIP_TABLE_SIZE << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and SHiP reuse histogram
}