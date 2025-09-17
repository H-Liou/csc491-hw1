#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- SRRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Dead-block predictor: per-line 2-bit counter ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: Signature table ----
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- Streaming detector: per-set monotonicity ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set (paddr)
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
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

    // SRRIP: select block with max RRPV (3)
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

    // ---- SHiP signature extraction ----
    uint16_t sig = (uint16_t)((PC >> 2) & 0x3F); // 6 bits
    uint16_t ship_idx = sig;
    line_sig[set][way] = sig;

    // ---- Dead-block predictor update ----
    if (hit) {
        dead_ctr[set][way] = 0; // reset on reuse
    } else {
        // On eviction, increment dead counter (max 3)
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // ---- SHiP outcome update ----
    if (hit) {
        rrpv[set][way] = 0; // promote on hit
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
    } else {
        // Penalize previous signature
        uint16_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
    }

    // ---- Insertion policy ----
    // If streaming detected OR dead predicted, bypass (do not insert, set RRPV=3)
    bool bypass = streaming || (dead_ctr[set][way] >= 2);

    uint8_t insertion_rrpv = 3; // default: insert at LRU (bypass)
    if (!bypass) {
        // SHiP bias: high-reuse signature inserts at MRU (0)
        if (ship_table[ship_idx].reuse_counter >= 2)
            insertion_rrpv = 0;
        else
            insertion_rrpv = 2; // SRRIP default
    }
    rrpv[set][way] = insertion_rrpv;
    line_sig[set][way] = sig;

    // ---- Periodic decay of dead counters and SHiP counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < LLC_SETS; ++i)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[i][w] > 0)
                    dead_ctr[i][w]--;
        for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
            if (ship_table[i].reuse_counter > 0)
                ship_table[i].reuse_counter--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    int dead_lines = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[i][w] >= 2) dead_lines++;
    std::cout << "ADSB Policy: Adaptive Dead-Streaming Bypass" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead-predicted lines: " << dead_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    int dead_lines = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[i][w] >= 2) dead_lines++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead-predicted lines (heartbeat): " << dead_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}