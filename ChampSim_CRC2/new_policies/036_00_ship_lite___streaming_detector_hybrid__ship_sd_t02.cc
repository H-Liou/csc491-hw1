#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: 6-bit signature per block, 2-bit outcome counter per signature ----
#define SIG_BITS 6
#define SIG_ENTRIES (1 << SIG_BITS)
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block
uint8_t ship_ctr[SIG_ENTRIES];         // 2 bits per signature

// ---- Streaming Detector: 8 bits per set ----
uint8_t last_delta[LLC_SETS]; // 8 bits per set
uint8_t stream_count[LLC_SETS]; // 8 bits per set

#define STREAM_THRESH 8 // If 8 consecutive accesses with same delta, treat as streaming

// ---- Other bookkeeping ----
uint64_t access_counter = 0;

void InitReplacementState() {
    // Initialize RRIP, SHiP, and streaming detector
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        last_delta[set] = 0;
        stream_count[set] = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // default distant insertion
            block_sig[set][way] = 0;
        }
    }
    for (uint32_t i = 0; i < SIG_ENTRIES; ++i)
        ship_ctr[i] = 1; // neutral initial value
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

    // --- Streaming Detector ---
    static uint64_t last_addr[LLC_SETS] = {0};
    uint8_t cur_delta = (uint8_t)(paddr - last_addr[set]);
    if (access_counter > 1) {
        if (cur_delta == last_delta[set] && cur_delta != 0) {
            if (stream_count[set] < 255) stream_count[set]++;
        } else {
            stream_count[set] = 1;
            last_delta[set] = cur_delta;
        }
    }
    last_addr[set] = paddr;

    // --- SHiP-lite signature ---
    uint8_t sig = (uint8_t)((PC ^ (paddr >> 6)) & (SIG_ENTRIES - 1));
    block_sig[set][way] = sig;

    // --- SHiP outcome update ---
    if (hit) {
        // On hit, block reused: increment outcome counter
        if (ship_ctr[sig] < 3) ship_ctr[sig]++;
        rrpv[set][way] = 0; // promote to MRU
    } else {
        // On miss, decrement outcome counter
        if (ship_ctr[sig] > 0) ship_ctr[sig]--;
    }

    // --- Insertion policy ---
    if (stream_count[set] >= STREAM_THRESH) {
        // Streaming detected: bypass or insert at LRU
        rrpv[set][way] = 3;
    } else {
        // SHiP-guided insertion
        if (ship_ctr[sig] >= 2)
            rrpv[set][way] = 0; // hot signature: insert at MRU
        else
            rrpv[set][way] = 2; // cold signature: insert at distant
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_sigs = 0;
    for (uint32_t i = 0; i < SIG_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) hot_sigs++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_count[set] >= STREAM_THRESH) streaming_sets++;
    std::cout << "SHiP-SD Policy: SHiP-lite + Streaming Detector Hybrid" << std::endl;
    std::cout << "Hot signatures (ctr>=2): " << hot_sigs << "/" << SIG_ENTRIES << std::endl;
    std::cout << "Streaming sets (count>=" << STREAM_THRESH << "): " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int hot_sigs = 0;
    for (uint32_t i = 0; i < SIG_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) hot_sigs++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_count[set] >= STREAM_THRESH) streaming_sets++;
    std::cout << "Hot signatures (heartbeat): " << hot_sigs << "/" << SIG_ENTRIES << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}