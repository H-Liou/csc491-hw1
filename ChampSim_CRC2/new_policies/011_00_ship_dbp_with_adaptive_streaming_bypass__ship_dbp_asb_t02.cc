#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite Metadata ---
#define SIG_BITS 6
#define SHIP_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- Dead-block Predictor Metadata ---
uint8_t dbp_ctr[LLC_SETS][LLC_WAYS];        // 2-bit per block, decayed periodically

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming Detector Metadata ---
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN]; // last 4 addresses per set
uint8_t stream_hist_ptr[LLC_SETS]; // circular pointer per set

// --- Streaming Miss Rate Metadata ---
#define MISS_WINDOW 32
uint8_t miss_window_ctr[LLC_SETS]; // 6 bits per set, sliding window miss count

// --- Streaming Detector Thresholds ---
#define STREAM_DETECT_COUNT 3 // at least 3 matching deltas
#define STREAM_BYPASS_RRPV 3  // insert at distant RRPV (or bypass)
#define MISS_RATE_THRESH 24   // if >24 misses in window, treat as streaming

// --- Periodic DBP decay ---
#define DBP_DECAY_INTERVAL 4096
uint64_t global_access_counter = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start at weak reuse
    memset(dbp_ctr, 1, sizeof(dbp_ctr));   // Start at weak reuse
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    memset(miss_window_ctr, 0, sizeof(miss_window_ctr));
    global_access_counter = 0;
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// --- Streaming Detector: returns true if streaming detected ---
bool is_streaming(uint32_t set, uint64_t paddr) {
    // Compute delta from last access
    uint8_t ptr = stream_hist_ptr[set];
    uint64_t last_addr = 0;
    if (ptr > 0)
        last_addr = stream_addr_hist[set][(ptr - 1) % STREAM_HIST_LEN];
    int64_t delta = 0;
    if (last_addr != 0)
        delta = (int64_t)paddr - last_addr;
    // Update history
    stream_addr_hist[set][ptr] = paddr;
    stream_hist_ptr[set] = (ptr + 1) % STREAM_HIST_LEN;
    // Check for monotonic deltas
    if (ptr < STREAM_HIST_LEN)
        return false; // not enough history yet
    int64_t ref_delta = stream_addr_hist[set][1] - stream_addr_hist[set][0];
    int match = 0;
    for (int i = 2; i < STREAM_HIST_LEN; ++i) {
        int64_t d = stream_addr_hist[set][i] - stream_addr_hist[set][i-1];
        if (d == ref_delta) match++;
    }
    return (match >= STREAM_DETECT_COUNT - 1);
}

// --- Adaptive Streaming Bypass: returns true if streaming or high miss rate detected ---
bool should_bypass_streaming(uint32_t set, uint64_t paddr) {
    bool streaming = is_streaming(set, paddr);
    bool high_miss = (miss_window_ctr[set] >= MISS_RATE_THRESH);
    return streaming || high_miss;
}

// --- Victim selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
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
    global_access_counter++;

    uint8_t sig = get_signature(PC);

    // --- Miss rate window update ---
    if (!hit) {
        if (miss_window_ctr[set] < MISS_WINDOW) miss_window_ctr[set]++;
    } else {
        if (miss_window_ctr[set] > 0) miss_window_ctr[set]--;
    }

    // --- Periodic DBP decay ---
    if ((global_access_counter & (DBP_DECAY_INTERVAL - 1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dbp_ctr[s][w] > 0) dbp_ctr[s][w]--;
    }

    // On hit: promote block, increment reuse counters
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        if (dbp_ctr[set][way] < 3) dbp_ctr[set][way]++;
        return;
    }

    // --- SHiP bias: if strong reuse, insert at MRU ---
    uint8_t insertion_rrpv = 2; // default
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    // --- Dead-block predictor: if block is likely dead, insert at distant RRPV ---
    if (dbp_ctr[set][way] == 0)
        insertion_rrpv = 3;

    // --- Adaptive Streaming Bypass: if streaming or high miss rate, insert at distant RRPV ---
    if (should_bypass_streaming(set, paddr))
        insertion_rrpv = STREAM_BYPASS_RRPV;

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1;
    dbp_ctr[set][way] = 1;
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0;
    int dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dbp_ctr[s][w] == 0) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "SHiP-DBP-ASB Policy: SHiP-lite + Dead-block predictor + Adaptive Streaming Bypass" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Blocks predicted dead (DBP ctr==0): " << dead_blocks << "/" << total_blocks << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0;
    int dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dbp_ctr[s][w] == 0) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks
              << " | Dead blocks: " << dead_blocks << "/" << total_blocks << std::endl;
}