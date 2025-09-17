#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set last address/stride, per-PC streaming score ---
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];

// --- Per-PC streaming score: 4 bits per entry, 64-entry table ---
#define PC_TABLE_SIZE 64
uint8_t pc_stream_score[PC_TABLE_SIZE]; // 0-15, streaming if >= 8

// --- Parameters ---
#define STREAM_SCORE_MAX 15
#define STREAM_SCORE_MIN 0
#define STREAM_SCORE_THRESHOLD 8
#define SRRIP_INSERT_RRPV 2

// Helper: get PC index (6 bits)
inline uint8_t get_pc_index(uint64_t PC) {
    return ((PC >> 2) ^ (PC >> 8)) & (PC_TABLE_SIZE - 1);
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way] = SRRIP_INSERT_RRPV;
        last_addr[set] = 0;
        last_stride[set] = 0;
    }
    for (int i = 0; i < PC_TABLE_SIZE; ++i)
        pc_stream_score[i] = STREAM_SCORE_MIN;
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
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
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
    uint8_t pc_idx = get_pc_index(PC);

    if (last_addr[set] != 0 && stride == last_stride[set] && stride != 0) {
        // Monotonic stride: likely streaming
        if (pc_stream_score[pc_idx] < STREAM_SCORE_MAX)
            pc_stream_score[pc_idx]++;
    } else {
        // Not streaming: decay score
        if (pc_stream_score[pc_idx] > STREAM_SCORE_MIN)
            pc_stream_score[pc_idx]--;
    }
    last_addr[set] = paddr;
    last_stride[set] = stride;

    // --- Insertion/bypass logic ---
    if (hit) {
        // On hit, promote to MRU
        rrpv[set][way] = 0;
    } else {
        // On miss, insert new block
        if (pc_stream_score[pc_idx] >= STREAM_SCORE_THRESHOLD) {
            // Streaming detected for this PC: bypass or insert at distant RRPV
            rrpv[set][way] = 3; // Insert at LRU, likely to be replaced quickly
        } else {
            // Default SRRIP insertion
            rrpv[set][way] = SRRIP_INSERT_RRPV;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int streaming_pcs = 0, nonstreaming_pcs = 0;
    for (int i = 0; i < PC_TABLE_SIZE; ++i) {
        if (pc_stream_score[i] >= STREAM_SCORE_THRESHOLD)
            streaming_pcs++;
        else
            nonstreaming_pcs++;
    }
    std::cout << "SRRIP-PCS: Streaming PCs: " << streaming_pcs
              << " / " << PC_TABLE_SIZE << std::endl;
    std::cout << "SRRIP-PCS: Non-streaming PCs: " << nonstreaming_pcs << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_pcs = 0;
    for (int i = 0; i < PC_TABLE_SIZE; ++i)
        if (pc_stream_score[i] >= STREAM_SCORE_THRESHOLD)
            streaming_pcs++;
    std::cout << "SRRIP-PCS: Streaming PCs: " << streaming_pcs << std::endl;
}