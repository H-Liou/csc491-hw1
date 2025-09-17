#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];         // 2 bits/line
uint8_t signature[LLC_SETS][LLC_WAYS];    // 6 bits/line
uint8_t ship_table[4096];                 // 2 bits/signature

// --- Streaming detector ---
uint64_t last_addr[LLC_SETS];
int8_t last_stride[LLC_SETS];
uint8_t stream_score[LLC_SETS];           // 2 bits/set

// --- Helper: hash PC to 6-bit signature ---
inline uint8_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// --- Helper: hash signature to SHiP table index ---
inline uint16_t ship_index(uint8_t sig) {
    return sig;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(signature, 0, sizeof(signature));
    memset(ship_table, 1, sizeof(ship_table)); // Neutral start
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_stride, 0, sizeof(last_stride));
    memset(stream_score, 0, sizeof(stream_score));
}

// --- Victim selection: SRRIP ---
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
    // --- Streaming detector ---
    int8_t stride = 0;
    if (last_addr[set] != 0)
        stride = (int8_t)((paddr >> 6) - (last_addr[set] >> 6));
    last_addr[set] = paddr;

    // Update stream_score: if stride matches last_stride and nonzero, increment; else reset
    if (stride == last_stride[set] && stride != 0) {
        if (stream_score[set] < 3) stream_score[set]++;
    } else {
        stream_score[set] = 0;
        last_stride[set] = stride;
    }
    bool is_streaming = (stream_score[set] >= 2);

    // --- SHiP-lite signature ---
    uint8_t sig = get_signature(PC);
    uint16_t idx = ship_index(sig);

    // --- On cache hit ---
    if (hit) {
        // Promote to MRU
        rrpv[set][way] = 0;
        // Update SHiP table: increment outcome counter (max 3)
        if (ship_table[idx] < 3) ship_table[idx]++;
    } else {
        // On fill: streaming bypass logic
        if (is_streaming) {
            // Streaming detected: bypass (insert at LRU)
            rrpv[set][way] = 3;
        } else {
            // Use SHiP outcome to bias insertion
            signature[set][way] = sig;
            if (ship_table[idx] >= 2) {
                rrpv[set][way] = 0; // Insert at MRU if signature is reusable
            } else {
                rrpv[set][way] = 2; // Insert at distant otherwise
            }
        }
    }

    // --- On eviction: update SHiP table if dead (not reused) ---
    if (!hit && victim_addr) {
        // Find victim way (the way being replaced)
        uint8_t victim_sig = signature[set][way];
        uint16_t victim_idx = ship_index(victim_sig);
        // If block was not reused (i.e., not promoted to MRU before eviction), decrement
        if (ship_table[victim_idx] > 0) ship_table[victim_idx]--;
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "SLSB: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    int reusable = 0;
    for (uint32_t i = 0; i < 64; ++i)
        if (ship_table[i] >= 2) reusable++;
    std::cout << "SLSB: SHiP reusable signatures: " << reusable << " / 64" << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "SLSB: Streaming sets: " << streaming_sets << std::endl;
}