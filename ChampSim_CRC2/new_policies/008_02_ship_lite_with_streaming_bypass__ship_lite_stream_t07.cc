#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-Lite Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];           // 2 bits/line: RRIP state
uint8_t line_sig[LLC_SETS][LLC_WAYS];       // 6 bits/line: PC signature
#define SIG_TABLE_SIZE 16                   // Per-set: 16-entry outcome table
uint8_t sig_outcome[LLC_SETS][SIG_TABLE_SIZE]; // 2 bits/entry: saturating counter

// --- Streaming Detector (per-set) ---
uint64_t last_addr[LLC_SETS];               // Last address seen in set
int8_t stream_score[LLC_SETS];              // Streaming confidence: -8..8

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));           // Initialize all RRPV to 3 (LRU)
    memset(line_sig, 0, sizeof(line_sig));
    memset(sig_outcome, 1, sizeof(sig_outcome)); // Weakly reused
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
}

// --- Victim selection (standard SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // SRRIP victim selection: evict max RRPV
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Streaming Detection: returns true if streaming detected ---
bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    // Only consider small, monotonic strides
    if (delta == 64 || delta == -64) {
        if (stream_score[set] < 8) stream_score[set]++;
    } else {
        if (stream_score[set] > -8) stream_score[set]--;
    }
    last_addr[set] = paddr;
    // Streaming if confidence high
    return stream_score[set] >= 5;
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
    // Compute signature from PC (6 bits)
    uint8_t sig = champsim_crc2(PC, set) & 0x3F;
    uint8_t idx = sig % SIG_TABLE_SIZE;

    // Update streaming detector
    bool streaming = IsStreaming(set, paddr);

    if (hit) {
        // On hit: promote to MRU, increment outcome counter (max 3)
        rrpv[set][way] = 0;
        if (sig_outcome[set][idx] < 3) sig_outcome[set][idx]++;
    } else {
        // On fill: record signature for the line
        line_sig[set][way] = sig;

        // Streaming blocks: bypass (do not cache) with high probability
        if (streaming) {
            // Insert at distant RRPV (3), rarely at 2
            rrpv[set][way] = ((rand() % 16) == 0) ? 2 : 3;
        } else {
            // If outcome counter for signature is low, insert at distant RRPV
            if (sig_outcome[set][idx] <= 1)
                rrpv[set][way] = 3; // Predicted dead
            else
                rrpv[set][way] = 2; // Predicted reused
        }
    }

    // On eviction: penalize non-reused signatures
    if (!hit) {
        uint8_t victim_sig = line_sig[set][way];
        uint8_t v_idx = victim_sig % SIG_TABLE_SIZE;
        if (sig_outcome[set][v_idx] > 0)
            sig_outcome[set][v_idx]--; // Decay on eviction
    }
}

// --- Stats ---
void PrintStats() {
    int reused = 0, dead = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
            if (sig_outcome[set][i] >= 2) reused++;
            else dead++;
    std::cout << "SHiP-Lite+Stream: Reused sigs: " << reused << " / " << (LLC_SETS * SIG_TABLE_SIZE) << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 5) streaming_sets++;
    std::cout << "SHiP-Lite+Stream: sets streaming: " << streaming_sets << " / " << LLC_SETS << std::endl;
}