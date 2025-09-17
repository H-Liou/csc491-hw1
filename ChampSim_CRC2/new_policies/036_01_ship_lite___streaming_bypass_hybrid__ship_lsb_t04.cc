#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: 6-bit signature per block, 2-bit outcome table ----
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 2048 // 2K entries
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block
uint8_t ship_table[SHIP_SIG_ENTRIES];  // 2 bits per entry

// ---- Streaming detector: 1 byte per set ----
uint64_t last_addr[LLC_SETS];       // Last address accessed in set
int8_t stream_score[LLC_SETS];      // [-8,8] streaming confidence

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define STREAM_SCORE_MAX 8
#define STREAM_SCORE_MIN -8
#define STREAM_DETECT_THRESHOLD 6

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;        // Default distant insertion
            block_sig[set][way] = 0;
        }
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        ship_table[i] = 1; // Neutral reuse
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
            if (rrpv[set][way] < 3)
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

    // --- Streaming detector update ---
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    if (delta == 64 || delta == -64) {
        // Typical streaming stride (cache line size)
        if (stream_score[set] < STREAM_SCORE_MAX)
            stream_score[set]++;
    } else {
        if (stream_score[set] > STREAM_SCORE_MIN)
            stream_score[set]--;
    }
    last_addr[set] = paddr;

    // --- SHiP-lite signature calculation ---
    uint16_t sig = (PC ^ (paddr >> 6)) & SHIP_SIG_MASK; // Mix PC and block address

    // --- Streaming bypass logic ---
    if (stream_score[set] >= STREAM_DETECT_THRESHOLD) {
        // Streaming detected: bypass on miss, or insert at LRU
        if (!hit) {
            // Bypass: do not cache this block (simulate by setting RRPV=3 and not updating signature)
            rrpv[set][way] = 3;
            block_sig[set][way] = sig;
            // No ship_table update for bypassed blocks
            return;
        }
        // On hit, treat as normal
    }

    // --- SHiP-lite update ---
    if (hit) {
        // Block reused: increment outcome counter (max 3)
        if (ship_table[block_sig[set][way]] < 3)
            ship_table[block_sig[set][way]]++;
        rrpv[set][way] = 0; // Promote to MRU
    } else {
        // Block not reused: decrement outcome counter (min 0)
        if (ship_table[sig] > 0)
            ship_table[sig]--;
    }

    // --- Insertion policy ---
    block_sig[set][way] = sig;
    if (ship_table[sig] >= 2) {
        // Reused signature: insert at MRU (RRPV=0)
        rrpv[set][way] = 0;
    } else {
        // Not reused: insert at distant (RRPV=2)
        rrpv[set][way] = 2;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int reused_blocks = 0;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESHOLD)
            streaming_sets++;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 0) reused_blocks++;
    std::cout << "SHiP-LSB Policy: SHiP-lite + Streaming Bypass Hybrid" << std::endl;
    std::cout << "MRU blocks: " << reused_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESHOLD)
            streaming_sets++;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}