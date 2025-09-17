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

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Dead-block counter ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming Detector Metadata ---
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN]; // last 4 addresses per set
uint8_t stream_hist_ptr[LLC_SETS]; // circular pointer per set

// --- Streaming Detector Thresholds ---
#define STREAM_DETECT_COUNT 3 // at least 3 matching deltas
#define STREAM_BYPASS_RRPV 3  // insert at distant RRPV (or bypass)

// --- Dead-block decay epoch ---
uint64_t global_access_counter = 0;
#define DEADBLOCK_DECAY_EPOCH 4096

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start at weak reuse
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    global_access_counter = 0;
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// --- Streaming Detector: returns true if streaming detected ---
bool is_streaming(uint32_t set, uint64_t paddr) {
    uint8_t ptr = stream_hist_ptr[set];
    stream_addr_hist[set][ptr] = paddr;
    stream_hist_ptr[set] = (ptr + 1) % STREAM_HIST_LEN;
    if (ptr < STREAM_HIST_LEN - 1)
        return false; // not enough history yet
    int64_t ref_delta = (int64_t)stream_addr_hist[set][1] - (int64_t)stream_addr_hist[set][0];
    int match = 0;
    for (int i = 2; i < STREAM_HIST_LEN; ++i) {
        int64_t d = (int64_t)stream_addr_hist[set][i] - (int64_t)stream_addr_hist[set][i-1];
        if (d == ref_delta) match++;
    }
    return (match >= STREAM_DETECT_COUNT - 1);
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

    // Dead-block preference: choose block with highest dead_ctr, else RRIP
    uint32_t victim = 0;
    uint8_t max_dead = dead_ctr[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (dead_ctr[set][way] > max_dead) {
            max_dead = dead_ctr[set][way];
            victim = way;
        }
    }
    // If multiple blocks have max dead_ctr, pick one with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == max_dead && rrpv[set][way] == 3)
            return way;

    // Otherwise, RRIP victim selection
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

    // --- Dead-block decay ---
    if ((global_access_counter & (DEADBLOCK_DECAY_EPOCH-1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }

    // On hit: promote block, increment SHiP reuse counter, reset dead_ctr
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        dead_ctr[set][way] = 0;
        return;
    }

    // --- Streaming detector ---
    bool streaming = is_streaming(set, paddr);

    // --- SHiP bias: if strong reuse, insert at MRU ---
    uint8_t insertion_rrpv = 2; // Default SRRIP
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    // --- Dead-block bias: if block is dead, insert at LRU ---
    if (dead_ctr[set][way] >= 2)
        insertion_rrpv = 3;

    // --- Streaming bypass: if streaming detected, insert at distant RRPV ---
    if (streaming)
        insertion_rrpv = STREAM_BYPASS_RRPV;

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1;

    // --- Dead-block update: increment counter on eviction ---
    if (!hit)
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;

}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dead_ctr[s][w] == 3) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "SHiP-Deadblock-ASB Policy: SHiP-lite + Dead-block counter + Adaptive Streaming Bypass" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Blocks marked dead (dead_ctr==3): " << dead_blocks << "/" << total_blocks << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dead_ctr[s][w] == 3) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << total_blocks << std::endl;
}