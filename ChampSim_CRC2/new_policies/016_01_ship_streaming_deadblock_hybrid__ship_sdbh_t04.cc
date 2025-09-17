#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit PC signature table, 2-bit outcome counter
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 entries
uint8_t ship_counter[LLC_SETS][SHIP_SIG_ENTRIES]; // 2 bits per entry
uint8_t block_sig[LLC_SETS][LLC_WAYS];           // 6 bits per block

// Streaming detector: per-set, last address and delta, 2-bit streaming counter
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// Dead-block: 2-bit counter per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// RRIP: 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Initialize replacement state
void InitReplacementState() {
    memset(ship_counter, 1, sizeof(ship_counter)); // neutral initial bias
    memset(block_sig, 0, sizeof(block_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(rrpv, 3, sizeof(rrpv));
}

// Streaming detector (called on every access/fill)
void UpdateStreamingDetector(uint32_t set, uint64_t paddr) {
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        // Monotonic stride detected, saturate counter
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        // Not streaming, decay counter
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
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
    // Dead-block: prefer invalid or dead-predicted blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (!current_set[way].valid)
            return way;
        if (dead_ctr[set][way] == 3)
            return way;
    }
    // Standard RRIP victim search
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
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
    // --- Streaming detection ---
    UpdateStreamingDetector(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = (PC ^ (PC >> 8)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: promote to MRU, update SHiP and dead counter
    if (hit) {
        rrpv[set][way] = 0;
        dead_ctr[set][way] = 0;
        // SHiP: increment outcome counter for signature
        if (ship_counter[set][block_sig[set][way]] < 3)
            ship_counter[set][block_sig[set][way]]++;
        return;
    }

    // --- On miss/fill: decide insertion depth ---
    uint8_t ins_rrpv = 2; // default SRRIP insertion
    // SHiP: if signature is reused, insert at MRU
    if (ship_counter[set][sig] >= 2)
        ins_rrpv = 0;
    else
        ins_rrpv = 3; // distant RRPV for cold/streaming/unknown signatures

    // Streaming: if streaming detected, force distant RRPV or bypass
    if (stream_ctr[set] >= 2)
        ins_rrpv = 3;

    // Dead-block: if predicted dead, force distant RRPV
    if (dead_ctr[set][way] == 3)
        ins_rrpv = 3;

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // Dead-block update: if evicted without reuse, increment dead counter
    if (dead_ctr[set][way] < 3)
        dead_ctr[set][way]++;
    else
        dead_ctr[set][way] = 3; // saturate

    // On fill, reset dead counter if not predicted dead
    if (ins_rrpv != 3)
        dead_ctr[set][way] = 0;

    // SHiP: if block inserted at distant RRPV, decrement outcome counter
    if (ship_counter[set][sig] > 0 && ins_rrpv == 3)
        ship_counter[set][sig]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Dead-block counter histogram
    uint64_t db_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            db_hist[dead_ctr[s][w]]++;
    std::cout << "SHiP-SDBH: Dead-block counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << db_hist[i] << " ";
    std::cout << std::endl;

    // SHiP counter histogram
    uint64_t ship_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
            ship_hist[ship_counter[s][i]]++;
    std::cout << "SHiP-SDBH: SHiP outcome counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age dead counters (avoid stuck dead prediction)
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] > 0)
                dead_ctr[s][w]--;
    // Periodic decay: age streaming counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] > 0)
            stream_ctr[s]--;
}