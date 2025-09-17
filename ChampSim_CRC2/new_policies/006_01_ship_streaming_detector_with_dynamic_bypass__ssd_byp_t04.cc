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
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Streaming detector metadata ---
uint8_t stream_delta_hist[LLC_SETS];      // 1 byte per set: last delta
uint8_t stream_confidence[LLC_SETS];      // 2 bits per set: streaming confidence

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_table, 1, sizeof(ship_table)); // optimistic: assume some reuse
    memset(stream_delta_hist, 0, sizeof(stream_delta_hist));
    memset(stream_confidence, 0, sizeof(stream_confidence));
}

// --- SHiP signature hash ---
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & (SHIP_TABLE_SIZE - 1);
}

// --- Streaming detector update ---
inline void UpdateStreamingDetector(uint32_t set, uint64_t paddr) {
    // Use block address (ignore offset bits)
    uint64_t blk_addr = paddr >> 6;
    static uint64_t last_blk_addr[LLC_SETS] = {0};

    uint8_t delta = (uint8_t)(blk_addr - last_blk_addr[set]);
    last_blk_addr[set] = blk_addr;

    // If delta is small and consistent, increase confidence
    if (delta == stream_delta_hist[set]) {
        if (stream_confidence[set] < 3) ++stream_confidence[set];
    } else {
        if (stream_confidence[set] > 0) --stream_confidence[set];
        stream_delta_hist[set] = delta;
    }
}

// --- Streaming decision ---
inline bool IsStreamingSet(uint32_t set) {
    return stream_confidence[set] >= 2;
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
    // --- Streaming detector update ---
    UpdateStreamingDetector(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        if (ship_table[sig] < 3) ++ship_table[sig];
        return;
    }

    // --- On fill ---
    ship_signature[set][way] = sig;

    // Streaming set: bypass or insert at distant RRPV
    if (IsStreamingSet(set)) {
        rrpv[set][way] = 3;
        return;
    }

    // SHiP advice: dead signature, insert at distant RRPV
    if (ship_table[sig] == 0) {
        rrpv[set][way] = 3;
        return;
    }

    // Otherwise, insert at MRU for "live" signatures
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

// --- Print statistics ---
void PrintStats() {
    std::cout << "SSD-BYP Policy: SHiP-lite + Streaming Detector + Dynamic Bypass\n";
}
void PrintStats_Heartbeat() {}