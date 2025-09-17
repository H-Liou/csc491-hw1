#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP Metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- SHiP-lite: per-line signature, global outcome table ---
static uint8_t pc_sig[LLC_SETS][LLC_WAYS];      // 6 bits per line (0-63)
static uint8_t ship_ctr[4096];                  // 2 bits per signature

// --- Streaming Detector ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Insert distant by default
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start neutral
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
}

// --- Streaming Detector ---
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

// --- SHiP-lite signature hash ---
inline uint16_t GetSignature(uint64_t PC) {
    // 6 bits: simple hash
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// --- SHiP-lite global table index ---
inline uint16_t GetShipIndex(uint8_t sig) {
    // 4096-entry table: sig + set index bits
    // Use lower 6 bits of set, 6 bits of sig
    return ((sig << 6) | (sig & 0x3F));
}

// --- Victim Selection ---
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
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
}

// --- Update Replacement State ---
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
    bool streaming = IsStreaming(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);
    uint16_t ship_idx = GetShipIndex(sig);

    // --- On hit: promote to MRU, increment SHiP counter ---
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[ship_idx] < 3) ship_ctr[ship_idx]++;
        return;
    }

    // --- On eviction: decrement SHiP counter if not reused ---
    uint8_t evict_sig = pc_sig[set][way];
    uint16_t evict_idx = GetShipIndex(evict_sig);
    if (ship_ctr[evict_idx] > 0) ship_ctr[evict_idx]--;

    // --- Insertion Policy ---
    // Streaming: always insert at distant RRPV
    if (streaming) {
        rrpv[set][way] = 3;
    } else {
        // SHiP outcome: high counter => insert MRU, else distant
        if (ship_ctr[ship_idx] >= 2)
            rrpv[set][way] = 0; // likely to be reused
        else
            rrpv[set][way] = 3; // likely dead
    }
    // Update signature for this line
    pc_sig[set][way] = sig;
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SSA Policy: SHiP-Lite + Streaming Bypass + Adaptive Insertion\n";
    // SHiP counter histogram
    uint32_t ship_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < 4096; ++i)
        ship_hist[ship_ctr[i]]++;
    std::cout << "SHiP counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
    // Streaming counter histogram
    uint32_t stream_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        stream_hist[stream_ctr[i]]++;
    std::cout << "Streaming counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}