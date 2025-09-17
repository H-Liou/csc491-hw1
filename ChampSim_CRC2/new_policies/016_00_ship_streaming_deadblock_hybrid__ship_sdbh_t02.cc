#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 2-bit outcome counter, 11-bit signature (PC lower bits)
#define SHIP_SIG_BITS 11
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_TABLE_SIZE]; // 2 bits per entry

// Per-block: 2-bit dead-block counter
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// Per-set streaming detector: last address, stride, streaming counter
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// Helper: get SHiP signature from PC
inline uint32_t GetSHIPSig(uint64_t PC) {
    return PC & (SHIP_TABLE_SIZE - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(ship_table, 1, sizeof(ship_table)); // Neutral initial value
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_stride, 0, sizeof(last_stride));
    memset(stream_ctr, 0, sizeof(stream_ctr));
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
    // Prefer invalid or dead-predicted blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (!current_set[way].valid)
            return way;
        if (dead_ctr[set][way] == 3)
            return way;
    }
    // Standard RRIP victim search: use per-block RRPV (implicit via dead_ctr)
    // Find block with max dead_ctr, break ties by LRU
    uint32_t victim = 0;
    uint8_t max_dead = dead_ctr[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (dead_ctr[set][way] > max_dead) {
            max_dead = dead_ctr[set][way];
            victim = way;
        }
    }
    return victim;
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
    // --- Streaming detector ---
    int64_t stride = paddr - last_addr[set];
    if (last_addr[set] != 0) {
        if (stride == last_stride[set]) {
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
    }
    last_stride[set] = stride;
    last_addr[set] = paddr;

    // --- SHiP signature ---
    uint32_t sig = GetSHIPSig(PC);

    // --- Dead-block counter update ---
    if (hit) {
        // On hit: reset dead counter, reward SHiP
        dead_ctr[set][way] = 0;
        if (ship_table[sig] < 3) ship_table[sig]++;
        return;
    } else {
        // On miss/fill: increment dead counter if block was evicted without reuse
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
        else
            dead_ctr[set][way] = 3; // saturate
    }

    // --- Insertion depth logic ---
    uint8_t ins_rrpv = 2; // Default: mid RRPV

    // If streaming detected, insert at distant RRPV (or bypass if stream_ctr==3)
    if (stream_ctr[set] == 3) {
        ins_rrpv = 3;
        // Optionally: bypass fill for streaming blocks with dead prediction
        if (dead_ctr[set][way] == 3)
            return; // Do not fill, treat as bypass
    }

    // SHiP: if signature shows reuse, insert at MRU
    if (ship_table[sig] >= 2)
        ins_rrpv = 0; // Favor blocks with reuse

    // Dead-block: if predicted dead, force distant RRPV
    if (dead_ctr[set][way] == 3)
        ins_rrpv = 3;

    // On fill, reset dead counter if not predicted dead
    if (ins_rrpv != 3)
        dead_ctr[set][way] = 0;

    // No explicit RRPV array: dead_ctr acts as reuse proxy
    // (If you want explicit RRPV, add: rrpv[set][way] = ins_rrpv;)
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
    // SHiP table reuse histogram
    uint64_t ship_hist[4] = {0};
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        ship_hist[ship_table[i]]++;
    std::cout << "SHiP-SDBH: SHiP table histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age dead counters and streaming counters
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] > 0)
                dead_ctr[s][w]--;
        if (stream_ctr[s] > 0)
            stream_ctr[s]--;
    }
}