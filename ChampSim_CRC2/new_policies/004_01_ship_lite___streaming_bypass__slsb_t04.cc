#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES 4096 // 2^SHIP_SIG_BITS * 128 (for spread)
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2 bits per signature

uint8_t line_signature[LLC_SETS][LLC_WAYS]; // 5 bits per line

// --- Streaming detector ---
uint64_t last_addr[LLC_SETS];
int8_t last_stride[LLC_SETS];
uint8_t stream_score[LLC_SETS]; // 2 bits/set

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits/line

// --- Helper: signature hash ---
inline uint16_t get_signature(uint64_t PC) {
    // Simple hash: take lower bits and xor with higher bits
    return ((PC >> 2) ^ (PC >> 10)) & (SHIP_SIG_ENTRIES - 1);
}

// --- Initialization ---
void InitReplacementState() {
    memset(ship_outcome, 1, sizeof(ship_outcome)); // Neutral start
    memset(line_signature, 0, sizeof(line_signature));
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_stride, 0, sizeof(last_stride));
    memset(stream_score, 0, sizeof(stream_score));
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

    // --- SHiP signature ---
    uint16_t sig = get_signature(PC);

    // --- On fill ---
    if (!hit) {
        line_signature[set][way] = sig;

        if (is_streaming) {
            // Streaming detected: bypass (insert at LRU)
            rrpv[set][way] = 3;
        } else {
            // Use outcome counter to bias insertion
            if (ship_outcome[sig] >= 2) {
                rrpv[set][way] = 0; // Insert at MRU
            } else if (ship_outcome[sig] == 1) {
                rrpv[set][way] = 2; // Insert at distant
            } else {
                rrpv[set][way] = 3; // Insert at LRU
            }
        }
    } else {
        // On hit: promote to MRU
        rrpv[set][way] = 0;
        // Update outcome counter for signature
        uint16_t sig_hit = line_signature[set][way];
        if (ship_outcome[sig_hit] < 3) ship_outcome[sig_hit]++;
    }

    // --- Dead block approximation: on victim ---
    if (!hit) {
        uint16_t sig_victim = line_signature[set][way];
        if (ship_outcome[sig_victim] > 0) ship_outcome[sig_victim]--;
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "SLSB: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;

    int high_reuse = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_outcome[i] >= 2) high_reuse++;
    std::cout << "SLSB: High-reuse signatures: " << high_reuse << " / " << SHIP_SIG_ENTRIES << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "SLSB: Streaming sets: " << streaming_sets << std::endl;
}