#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signatures, 2-bit outcome per signature ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 64
uint8_t block_sig[LLC_SETS][LLC_WAYS];       // Per-block signature (6 bits)
uint8_t sig_outcome[SIG_TABLE_SIZE];         // 2-bit saturating counter per signature

// --- Dead-block: 1-bit per block (was_reused) ---
uint8_t dead_block_flag[LLC_SETS][LLC_WAYS]; // 0 = dead (not reused), 1 = reused

// --- SRRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, stride, monotonic counter (2 bits) ---
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];
uint8_t monotonic_count[LLC_SETS];
#define STREAM_THRESHOLD 2 // streaming if monotonic_count >= 2

// --- Simulated global cycle for temporal signature (low bits only) ---
uint64_t global_cycle = 0;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            dead_block_flag[set][way] = 1; // assume reused on startup
        }
        last_addr[set] = 0;
        last_stride[set] = 0;
        monotonic_count[set] = 0;
    }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_outcome[i] = 1;
    global_cycle = 0;
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
    // Standard SRRIP victim selection
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
    global_cycle += 1; // emulate time advancing

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
    uint8_t sig = ((PC >> 2) ^ (global_cycle & 0x3F)) & ((1 << SIG_BITS) - 1);

    if (hit) {
        rrpv[set][way] = 0; // promote to MRU
        dead_block_flag[set][way] = 1; // mark as reused
        if (sig_outcome[block_sig[set][way]] < 3)
            sig_outcome[block_sig[set][way]]++;
    } else {
        // On eviction, update dead-block flag and penalize outcome if not reused
        uint8_t victim_sig = block_sig[set][way];
        if (dead_block_flag[set][way] == 0) {
            // Block was not reused: penalize signature
            if (sig_outcome[victim_sig] > 0)
                sig_outcome[victim_sig]--;
        }
        // Insert new block with signature
        block_sig[set][way] = sig;
        dead_block_flag[set][way] = 0; // not reused yet

        // --- Streaming bypass logic ---
        bool stream_detected = (monotonic_count[set] >= STREAM_THRESHOLD);
        bool bypass_block = (stream_detected && sig_outcome[sig] < 2);

        if (bypass_block) {
            // Bypass: set RRPV to max so immediately evicted
            rrpv[set][way] = 3;
        } else {
            // --- Hybrid insertion depth ---
            if (sig_outcome[sig] >= 2 || dead_block_flag[set][way] == 1) {
                rrpv[set][way] = 0; // insert at MRU if signature hot or last block reused
            } else {
                rrpv[set][way] = 2; // insert at distant RRPV otherwise
            }
        }
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

    int dead_blocks = 0, reused_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_block_flag[set][way] == 0) dead_blocks++;
            else reused_blocks++;
    std::cout << "SHiP-DB-SB: Dead blocks: " << dead_blocks
              << ", Reused blocks: " << reused_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-DB-SB: Streaming sets: " << streaming_sets << std::endl;
}