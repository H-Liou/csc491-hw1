#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_MASK ((1ULL << SHIP_SIG_BITS) - 1)
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_counter[SHIP_TABLE_SIZE]; // 2 bits per entry

// Per-block signature storage
uint8_t block_sig[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, 2-bit counter, last address ---
uint64_t last_addr[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set
#define STREAM_THRESHOLD 3

// --- RRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(ship_counter, 1, sizeof(ship_counter)); // neutral start
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Streaming detector update ---
inline void update_streaming(uint32_t set, uint64_t paddr) {
    uint64_t last = last_addr[set];
    uint64_t delta = (last == 0) ? 0 : (paddr > last ? paddr - last : last - paddr);
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

    // On hit: promote block, increment reuse counter
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_counter[sig] < 3) ship_counter[sig]++;
    } else {
        // On miss: update block signature
        block_sig[set][way] = sig;

        // Streaming detected: bypass if signature is low reuse
        if (stream_ctr[set] >= STREAM_THRESHOLD && ship_counter[sig] == 0) {
            // Bypass: do not insert, leave block invalid (simulate by setting RRPV=3)
            rrpv[set][way] = 3;
            return;
        }

        // SHiP-lite insertion: high reuse => RRPV=2, low reuse => RRPV=3
        if (ship_counter[sig] >= 2)
            rrpv[set][way] = 2;
        else
            rrpv[set][way] = 3;
    }

    // On eviction: decrement reuse counter if block was not reused
    if (!hit && block_sig[set][way] != 0) {
        uint8_t evict_sig = block_sig[set][way];
        if (ship_counter[evict_sig] > 0) ship_counter[evict_sig]--;
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

    uint32_t high_reuse = 0, low_reuse = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_counter[i] >= 2) high_reuse++;
        if (ship_counter[i] == 0) low_reuse++;
    }
    std::cout << "High-reuse signatures: " << high_reuse << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Low-reuse signatures: " << low_reuse << "/" << SHIP_TABLE_SIZE << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and reuse signature stats
}