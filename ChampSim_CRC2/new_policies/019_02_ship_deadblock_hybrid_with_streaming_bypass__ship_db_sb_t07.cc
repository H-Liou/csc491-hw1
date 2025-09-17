#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 5-bit PC signature per block, 2-bit outcome counter per signature ---
#define SIG_BITS 5
#define SIG_TABLE_SIZE 32
uint8_t block_sig[LLC_SETS][LLC_WAYS];       // Per-block signature (5 bits)
uint8_t sig_outcome[SIG_TABLE_SIZE];         // 2-bit saturating counter per signature

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block predictor: 2-bit counter per block ---
uint8_t deadctr[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, stride, monotonic counter (2 bits) ---
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];
uint8_t monotonic_count[LLC_SETS];
#define STREAM_THRESHOLD 2 // streaming if monotonic_count >= 2

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            deadctr[set][way] = 0;
        }
        last_addr[set] = 0;
        last_stride[set] = 0;
        monotonic_count[set] = 0;
    }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_outcome[i] = 1;
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // 1. Try to evict a dead block first (deadctr==3, prefer high RRPV)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (deadctr[set][way] == 3 && rrpv[set][way] == 3)
            return way;
    }
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (deadctr[set][way] == 3)
            return way;
    }
    // 2. Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
    }
}

// Update replacement state
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
    int64_t stride = (last_addr[set] == 0) ? 0 : int64_t(paddr) - int64_t(last_addr[set]);
    if (last_addr[set] != 0 && stride == last_stride[set] && stride != 0) {
        if (monotonic_count[set] < 3) monotonic_count[set]++;
    } else {
        if (monotonic_count[set] > 0) monotonic_count[set]--;
    }
    last_addr[set] = paddr;
    last_stride[set] = stride;

    // --- SHiP signature ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x1F)) & ((1 << SIG_BITS) - 1);

    // --- Dead-block counter update ---
    if (hit) {
        rrpv[set][way] = 0; // promote to MRU
        if (deadctr[set][way] > 0) deadctr[set][way] = 0; // reset on hit
        // SHiP: promote signature if reused
        if (sig_outcome[block_sig[set][way]] < 3)
            sig_outcome[block_sig[set][way]]++;
    } else {
        // On eviction, penalize SHiP outcome if block was not reused
        uint8_t victim_sig = block_sig[set][way];
        if (sig_outcome[victim_sig] > 0)
            sig_outcome[victim_sig]--;

        // Insert new block with signature
        block_sig[set][way] = sig;

        // Streaming bypass logic
        bool stream_detected = (monotonic_count[set] >= STREAM_THRESHOLD);
        bool bypass_block = (stream_detected && sig_outcome[sig] < 2);

        if (bypass_block) {
            rrpv[set][way] = 3; // streaming bypass: insert as LRU
            deadctr[set][way] = 2; // mark as likely dead
        } else {
            // SHiP: hot signature gets MRU insert, else distant
            if (sig_outcome[sig] >= 2) {
                rrpv[set][way] = 0;
                deadctr[set][way] = 0;
            } else {
                rrpv[set][way] = 2;
                deadctr[set][way] = 1;
            }
        }
    }
    // Dead-block predictor aging: increment on miss, reset on hit (done above)
    if (!hit) {
        if (deadctr[set][way] < 3) deadctr[set][way]++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_sigs = 0, cold_sigs = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_outcome[i] >= 2) hot_sigs++;
        else cold_sigs++;
    }
    std::cout << "SHiP-DB-SB: Hot signatures: " << hot_sigs
              << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SHiP-DB-SB: Cold signatures: " << cold_sigs << std::endl;

    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-DB-SB: Streaming sets: " << streaming_sets
              << " / " << LLC_SETS << std::endl;

    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (deadctr[set][way] == 3) dead_blocks++;
    std::cout << "SHiP-DB-SB: Dead blocks: " << dead_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-DB-SB: Streaming sets: " << streaming_sets << std::endl;

    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (deadctr[set][way] == 3) dead_blocks++;
    std::cout << "SHiP-DB-SB: Dead blocks: " << dead_blocks << std::endl;
}