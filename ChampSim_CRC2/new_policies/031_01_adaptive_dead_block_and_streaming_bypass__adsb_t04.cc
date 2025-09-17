#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Per-line Dead-block counters ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Streaming detector: per-set monotonicity ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set (paddr)
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 3;
            dead_ctr[set][way] = 1; // initialize to weakly dead
        }
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    access_counter = 0;
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // RRIP: select block with max RRPV (3)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
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
    access_counter++;

    // ---- Streaming detector ----
    uint64_t last = last_addr[set];
    uint8_t score = stream_score[set];
    if (last == 0) {
        last_addr[set] = paddr;
        stream_score[set] = 0;
    } else {
        uint64_t delta = (paddr > last) ? (paddr - last) : (last - paddr);
        if (delta == 64 || delta == 128) { // 1-2 block stride
            if (score < 3) stream_score[set]++;
        } else {
            if (score > 0) stream_score[set]--;
        }
        last_addr[set] = paddr;
    }
    bool streaming = (stream_score[set] >= 2);

    // ---- Dead-block counter update ----
    if (hit) {
        // On hit, increase reuse confidence
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
        rrpv[set][way] = 0; // promote to MRU
    } else {
        // On miss, decrease reuse confidence
        if (dead_ctr[set][way] > 0)
            dead_ctr[set][way]--;
    }

    // ---- Insertion policy ----
    if (streaming) {
        // Streaming detected: bypass (set RRPV=3)
        rrpv[set][way] = 3;
    } else {
        // Dead-block predictor: insert at MRU if high reuse, at distant RRPV if dead
        if (dead_ctr[set][way] >= 2)
            rrpv[set][way] = 0; // high reuse, insert at MRU
        else
            rrpv[set][way] = 2; // weakly dead, insert at distant RRPV
    }

    // ---- Periodic decay of dead-block counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (dead_ctr[set][way] > 0)
                    dead_ctr[set][way]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_lines = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] >= 2) high_reuse_lines++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) streaming_sets++;
    std::cout << "ADSB Policy: Adaptive Dead-Block and Streaming Bypass" << std::endl;
    std::cout << "High-reuse lines: " << high_reuse_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_lines = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] >= 2) high_reuse_lines++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) streaming_sets++;
    std::cout << "High-reuse lines (heartbeat): " << high_reuse_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}