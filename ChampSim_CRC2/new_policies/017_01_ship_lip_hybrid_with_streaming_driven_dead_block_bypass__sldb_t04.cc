#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ----- SHiP-lite Metadata -----
#define SIG_BITS 6
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// ----- RRIP Metadata (for LIP) -----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ----- Streaming Detector Metadata -----
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN];
uint8_t stream_hist_ptr[LLC_SETS];
uint8_t stream_detected[LLC_SETS];

// ----- Dead-block Counter Metadata -----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ----- Periodic Decay -----
uint64_t access_counter = 0;
#define DECAY_PERIOD 4096

// ----- Initialization -----
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All blocks at LRU
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Weak reuse
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    memset(stream_detected, 0, sizeof(stream_detected));
    memset(dead_ctr, 2, sizeof(dead_ctr)); // Medium deadness
    access_counter = 0;
}

// ----- PC Signature hashing -----
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// ----- Streaming Detector: returns true if streaming detected -----
bool update_streaming(uint32_t set, uint64_t paddr) {
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
    stream_detected[set] = (match >= STREAM_HIST_LEN - 2) ? 1 : 0;
    return stream_detected[set];
}

// ----- Victim selection (LIP: prefer blocks with max RRPV) -----
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

    // LIP: select block with RRPV==3 (LRU)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

// ----- Update replacement state -----
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
    access_counter++;
    uint8_t sig = get_signature(PC);

    // --- Streaming detector ---
    bool streaming = update_streaming(set, paddr);

    // --- Dead-block counter decay (periodic) ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }

    // --- SHiP update ---
    if (hit) {
        rrpv[set][way] = 0; // MRU on hit
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
        return;
    }

    // --- Dead-block counter update on miss (potential dead block) ---
    if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;

    // --- SHiP counter decay (simple: on miss, weak reuse) ---
    if (ship_ctr[set][way] > 0) ship_ctr[set][way]--;

    // --- Insertion depth logic ---
    uint8_t insertion_rrpv = 3; // LIP: insert at LRU (RRPV=3)
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0; // SHiP strong reuse: insert at MRU

    // --- Streaming-aware dead-block bypass ---
    // If streaming detected AND (weak SHiP reuse) AND (dead_ctr==3), bypass
    if (streaming && ship_ctr[set][way] <= 1 && dead_ctr[set][way] == 3) {
        // Do not insert: leave block invalid
        rrpv[set][way] = 3;
        ship_signature[set][way] = sig;
        ship_ctr[set][way] = 1;
        dead_ctr[set][way] = 3;
        return;
    }

    // Insert block
    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // weak reuse on fill
    // dead_ctr unchanged on fill
}

// ----- Print end-of-simulation statistics -----
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dead_ctr[s][w] == 3) dead_blocks++;
            total_blocks++;
        }
    std::cout << "SLDB Policy: SHiP-LIP Hybrid + Streaming-Driven Dead-Block Bypass" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Blocks marked dead (dead_ctr==3): " << dead_blocks << "/" << total_blocks << std::endl;
}

// ----- Print periodic (heartbeat) statistics -----
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (dead_ctr[s][w] == 3) dead_blocks++;
            total_blocks++;
        }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << total_blocks << std::endl;
}