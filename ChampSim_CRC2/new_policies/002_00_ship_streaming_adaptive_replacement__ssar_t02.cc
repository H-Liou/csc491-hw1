#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2 bits/line: RRPV
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 6 bits/line: PC signature
uint8_t pc_sig[LLC_SETS][LLC_WAYS];

// SHiP table: 2K entries, 2 bits/counter
#define SHIP_TABLE_SIZE 2048
uint8_t ship_table[SHIP_TABLE_SIZE];

// Streaming detector: per-set last address and stride (8 bits/set)
uint64_t last_addr[LLC_SETS];
int8_t last_stride[LLC_SETS];
uint8_t stream_score[LLC_SETS]; // 2 bits/set

// Helper: hash PC to 6 bits
inline uint8_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 11) ^ (PC >> 17)) & 0x3F;
}

// Helper: hash signature to SHiP table index
inline uint16_t ship_index(uint8_t sig) {
    return sig ^ (sig >> 3);
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // Initialize to distant
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // Neutral reuse
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
    // Standard SRRIP: find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
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
    uint8_t sig = get_signature(PC);
    uint16_t idx = ship_index(sig);

    // --- Streaming detector ---
    int8_t stride = 0;
    if (last_addr[set] != 0)
        stride = (int8_t)((paddr >> 6) - (last_addr[set] >> 6)); // block granularity
    last_addr[set] = paddr;

    // Update stream_score: if stride matches last_stride, increment; else, reset
    if (stride == last_stride[set] && stride != 0) {
        if (stream_score[set] < 3) stream_score[set]++;
    } else {
        stream_score[set] = 0;
        last_stride[set] = stride;
    }

    // --- SHiP update ---
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_table[idx] < 3)
            ship_table[idx]++;
    } else {
        pc_sig[set][way] = sig;

        // Streaming phase detected: high stream_score and monotonic stride
        bool is_streaming = (stream_score[set] >= 2);

        uint8_t ship_score = ship_table[idx];

        // If streaming and low reuse, insert at distant (RRPV=2 or 3)
        if (is_streaming && ship_score <= 1) {
            rrpv[set][way] = 3; // Bypass: insert at LRU
        }
        // If streaming but signature has moderate reuse, insert at distant
        else if (is_streaming && ship_score == 2) {
            rrpv[set][way] = 2;
        }
        // If high-reuse signature, insert at MRU
        else if (ship_score >= 2) {
            rrpv[set][way] = 0;
        }
        // Otherwise, default distant insert
        else {
            rrpv[set][way] = 2;
        }
    }

    // On eviction: decay SHiP counter if not reused
    if (!hit) {
        uint8_t evict_sig = pc_sig[set][way];
        uint16_t evict_idx = ship_index(evict_sig);
        if (ship_table[evict_idx] > 0)
            ship_table[evict_idx]--;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SSAR: SHiP table (reuse counters) summary:" << std::endl;
    int reused = 0, total = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_table[i] >= 2) reused++;
        total++;
    }
    std::cout << "High-reuse signatures: " << reused << " / " << total << std::endl;
    // Streaming summary
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    // Print fraction of streaming sets
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "SSAR: Streaming sets: " << streaming_sets << std::endl;
}