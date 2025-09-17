#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits/line

// --- SHiP-lite: Per-set signature table ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 per set
uint8_t ship_sig[LLC_SETS][SHIP_SIG_ENTRIES]; // 2 bits per signature

// --- Streaming detector: per-set ---
uint8_t stream_state[LLC_SETS]; // 2 bits/set: 0=normal, 1=streaming, 2=confirmed streaming

// --- Per-set last address for streaming detection ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(ship_sig, 1, sizeof(ship_sig)); // Neutral SHiP counters
    memset(stream_state, 0, sizeof(stream_state));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
}

// --- Victim selection: standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if confirmed streaming, don't cache
    if (stream_state[set] == 2)
        return LLC_WAYS; // special value: bypass

    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
    }
}

// --- Replacement state update ---
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
    // --- Streaming detection ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0) {
        if (delta == last_delta[set] && delta != 0) {
            // Monotonic stride detected
            if (stream_state[set] < 2) stream_state[set]++;
        } else {
            if (stream_state[set] > 0) stream_state[set]--;
        }
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- SHiP signature: 6 bits from PC ---
    uint32_t sig = (PC ^ (PC >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- Streaming bypass logic ---
    if (stream_state[set] == 2) {
        // Confirmed streaming: bypass fill
        return;
    }

    // --- On cache hit ---
    if (hit) {
        // Promote to MRU
        rrpv[set][way] = 0;
        // Update SHiP outcome counter (max 3)
        if (ship_sig[set][sig] < 3) ship_sig[set][sig]++;
    } else {
        // On fill: SHiP-guided insertion
        if (ship_sig[set][sig] >= 2) {
            // Frequent reuse: insert at MRU
            rrpv[set][way] = 0;
        } else if (stream_state[set] == 1) {
            // Detected streaming: insert at distant RRPV (3)
            rrpv[set][way] = 3;
        } else {
            // Default SRRIP insertion
            rrpv[set][way] = 2;
        }
        // On miss, reset SHiP outcome counter (weakly not reused)
        if (ship_sig[set][sig] > 0) ship_sig[set][sig]--;
    }
}

// --- Stats ---
void PrintStats() {
    int ship_reused = 0, ship_total = 0, streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
            if (ship_sig[s][i] >= 2) ship_reused++;
            ship_total++;
        }
        if (stream_state[s] == 2) streaming_sets++;
    }
    std::cout << "SRRIP-SHiP-SB: SHiP reused sigs: " << ship_reused << " / " << ship_total << std::endl;
    std::cout << "SRRIP-SHiP-SB: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_state[s] == 2) streaming_sets++;
    std::cout << "SRRIP-SHiP-SB: Streaming sets: " << streaming_sets << std::endl;
}