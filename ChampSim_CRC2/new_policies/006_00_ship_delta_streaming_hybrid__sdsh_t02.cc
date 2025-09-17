#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite signature ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6 bits per line
uint8_t ship_table[SHIP_TABLE_SIZE];        // 2 bits per signature

// --- RRPV for SRRIP ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, 2-entry delta history, 2-bit streaming counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_table, 1, sizeof(ship_table)); // optimistic: assume some reuse
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
}

// --- SHiP signature hash ---
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & (SHIP_TABLE_SIZE - 1);
}

// --- Streaming detector update ---
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    bool streaming = false;
    if (last_delta[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) ++stream_ctr[set];
    } else {
        if (stream_ctr[set] > 0) --stream_ctr[set];
    }
    streaming = (stream_ctr[set] >= 2);
    last_delta[set] = delta;
    last_addr[set] = paddr;
    return streaming;
}

// --- Victim selection (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
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
    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        if (ship_table[sig] < 3) ++ship_table[sig];
        return;
    }

    // --- Streaming detection ---
    bool streaming = IsStreaming(set, paddr);

    // --- On fill ---
    ship_signature[set][way] = sig;

    // If streaming detected, insert at distant RRPV (bypass)
    if (streaming) {
        rrpv[set][way] = 3;
        return;
    }

    // SHiP advice: dead signature, insert at distant RRPV
    if (ship_table[sig] == 0) {
        rrpv[set][way] = 3;
        return;
    }

    // Otherwise, insert at MRU
    rrpv[set][way] = 0;
}

// --- On eviction: update SHiP ---
void OnEviction(
    uint32_t set, uint32_t way
) {
    uint8_t sig = ship_signature[set][way];
    // If not reused (RRPV==3), mark as dead in SHiP
    if (rrpv[set][way] == 3) {
        if (ship_table[sig] > 0) --ship_table[sig];
    }
}

// --- Periodic decay of SHiP table ---
void DecayMetadata() {
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i] > 0) --ship_table[i];
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SDSH Policy: SHiP-lite + Streaming Detector Hybrid\n";
}
void PrintStats_Heartbeat() {}