#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata: 2-bit RRPV per line ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-Lite: 6-bit signature per line, 2-bit outcome counter table (256 entries) ---
uint8_t ship_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line
uint8_t ship_ctr[256];                // 2 bits per signature

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(ship_sig, 0, sizeof(ship_sig));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // neutral confidence
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Victim selection: RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming phase: prefer to bypass lines with low SHiP confidence
    if (streaming_flag[set]) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            uint8_t sig = ship_sig[set][way];
            if (ship_ctr[sig] == 0 && rrpv[set][way] == 3)
                return way;
        }
    }
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
    // --- Streaming detector update (per set) ---
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- SHiP signature extraction ---
    uint8_t sig = (uint8_t)((PC ^ (PC >> 6)) & 0x3F); // 6-bit signature

    // --- SHiP outcome counter update ---
    if (hit) {
        // On hit, increment counter (max 3)
        if (ship_ctr[sig] < 3) ship_ctr[sig]++;
        rrpv[set][way] = 0; // Promote to MRU
    } else {
        // On miss, decrement counter for victim's signature
        uint8_t victim_sig = ship_sig[set][way];
        if (ship_ctr[victim_sig] > 0) ship_ctr[victim_sig]--;

        // --- Streaming phase: bypass if low SHiP confidence ---
        if (streaming_flag[set] && ship_ctr[sig] == 0) {
            rrpv[set][way] = 3; // Insert at LRU (effectively bypass)
        } else if (ship_ctr[sig] >= 2) {
            rrpv[set][way] = 0; // Insert at MRU if signature is confident
        } else {
            rrpv[set][way] = 3; // Insert at LRU otherwise
        }
        ship_sig[set][way] = sig; // Update signature
    }

    // --- Periodic decay of SHiP counters (every 4096 misses) ---
    static uint64_t global_miss_count = 0;
    if (!hit) {
        global_miss_count++;
        if ((global_miss_count & 0xFFF) == 0) { // every 4096 misses
            for (uint32_t i = 0; i < 256; ++i)
                if (ship_ctr[i] > 0) ship_ctr[i]--;
        }
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0, high_conf_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (streaming_flag[s]) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (ship_ctr[ship_sig[s][w]] >= 2) high_conf_lines++;
    }
    std::cout << "SHiP-LSB: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "SHiP-LSB: High-confidence lines: " << high_conf_lines << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-LSB: Streaming sets: " << streaming_sets << std::endl;
}