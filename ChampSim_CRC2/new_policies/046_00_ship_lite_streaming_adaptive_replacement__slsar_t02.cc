#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 5-bit PC signature, 2-bit outcome counter per block ---
uint8_t block_sig[LLC_SETS][LLC_WAYS];   // 5 bits per block
uint8_t block_outcome[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector: per-set, monitors recent address deltas ---
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];      // 3-bit signed: [-4, +3]
#define STREAM_SCORE_MIN -4
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_THRESH 2       // If score >=2, treat as streaming

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Periodic decay for outcome counters ---
uint64_t access_counter = 0;
#define DECAY_PERIOD (LLC_SETS * LLC_WAYS * 8)

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            block_outcome[set][way] = 1; // Neutral start
        }
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    access_counter = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
    }
}

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

    // --- Streaming detector update ---
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    if (delta == 64 || delta == -64) {
        if (stream_score[set] < STREAM_SCORE_MAX)
            stream_score[set]++;
    } else if (delta != 0) {
        if (stream_score[set] > STREAM_SCORE_MIN)
            stream_score[set]--;
    }
    last_addr[set] = paddr;

    // --- SHiP-lite signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & 0x1F; // 5 bits: mix PC and block address

    // --- Block outcome update ---
    if (hit) {
        // Block reused: increment outcome counter (max 3)
        if (block_outcome[set][way] < 3)
            block_outcome[set][way]++;
        rrpv[set][way] = 0; // MRU on hit
    } else {
        // Block evicted: decrement outcome counter (min 0)
        if (block_outcome[set][way] > 0)
            block_outcome[set][way]--;
    }

    // --- Periodic decay of outcome counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (block_outcome[s][w] > 0)
                    block_outcome[s][w]--;
    }

    // --- Streaming-aware insertion ---
    bool is_streaming = (stream_score[set] >= STREAM_DETECT_THRESH);

    // --- Insertion depth logic ---
    if (is_streaming) {
        // Streaming detected: insert at distant RRPV, bypass with probability 1/8
        if ((PC ^ paddr) & 0x7) {
            rrpv[set][way] = 3; // Bypass
        } else {
            rrpv[set][way] = 2; // Distant
        }
    }
    else if (block_outcome[set][way] >= 2) {
        // Good PC: insert at MRU
        rrpv[set][way] = 0;
    }
    else {
        // Bad PC: insert at LRU
        rrpv[set][way] = 2;
    }

    // --- Update block signature ---
    block_sig[set][way] = sig;
}

void PrintStats() {
    int good_blocks = 0, bad_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (block_outcome[set][way] >= 2) good_blocks++;
            if (block_outcome[set][way] == 0) bad_blocks++;
        }
    std::cout << "SLSAR: Good blocks (outcome>=2): " << good_blocks << " / " << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "SLSAR: Bad blocks (outcome==0): " << bad_blocks << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SLSAR: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    int good_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (block_outcome[set][way] >= 2) good_blocks++;
    std::cout << "SLSAR: Good blocks: " << good_blocks << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SLSAR: Streaming sets: " << stream_sets << std::endl;
}