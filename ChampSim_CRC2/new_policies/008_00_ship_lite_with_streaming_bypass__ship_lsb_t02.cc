#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];         // 2 bits/line
uint8_t pc_sig[LLC_SETS][LLC_WAYS];       // 6 bits/line: PC signature
#define SHIP_TABLE_SIZE 2048
uint8_t ship_table[SHIP_TABLE_SIZE];      // 2 bits/entry: outcome counter

// --- Streaming detector: per-set ---
uint64_t last_addr[LLC_SETS];             // last accessed address per set
int8_t stream_score[LLC_SETS];            // +ve: streaming, -ve: random
#define STREAM_THRESHOLD 8

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
}

// --- Victim selection: standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
    }
}

// --- Replacement state update ---
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
    // --- Streaming detector update ---
    uint64_t addr_delta = (last_addr[set] > 0) ? std::abs((int64_t)paddr - (int64_t)last_addr[set]) : 0;
    if (addr_delta == 64) // typical cache line stride
        stream_score[set]++;
    else if (addr_delta > 0 && addr_delta < 4096)
        stream_score[set]--;
    // Clamp score
    if (stream_score[set] > STREAM_THRESHOLD) stream_score[set] = STREAM_THRESHOLD;
    if (stream_score[set] < -STREAM_THRESHOLD) stream_score[set] = -STREAM_THRESHOLD;
    last_addr[set] = paddr;

    // --- SHiP signature ---
    uint8_t sig = champsim_crc2(PC, set) & 0x3F; // 6 bits

    // --- SHiP table index ---
    uint32_t ship_idx = sig ^ (set & 0x7FF); // 11 bits for set, 6 bits for sig

    if (hit) {
        // On hit: promote to MRU, update SHiP table
        rrpv[set][way] = 0;
        pc_sig[set][way] = sig;
        if (ship_table[ship_idx] < 3) ship_table[ship_idx]++;
    } else {
        // On fill: determine insertion depth
        pc_sig[set][way] = sig;
        uint8_t reuse = ship_table[ship_idx];

        // Streaming phase: bypass or insert at distant RRPV
        if (stream_score[set] >= STREAM_THRESHOLD) {
            rrpv[set][way] = 3; // streaming: insert at LRU
        } else {
            // SHiP: high reuse => MRU, low reuse => LRU
            if (reuse >= 2)
                rrpv[set][way] = 0; // insert at MRU
            else
                rrpv[set][way] = 2; // insert at mid
        }
    }

    // --- On eviction: update SHiP table ---
    if (!hit) {
        // Find victim's signature
        uint8_t victim_sig = pc_sig[set][way];
        uint32_t victim_idx = victim_sig ^ (set & 0x7FF);
        // If block was not reused, decrement SHiP counter
        if (rrpv[set][way] == 3 && ship_table[victim_idx] > 0)
            ship_table[victim_idx]--;
    }
}

// --- Stats ---
void PrintStats() {
    int reused = 0, total = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i] >= 2) reused++;
    std::cout << "SHiP-LSB: High-reuse signatures: " << reused << " / " << SHIP_TABLE_SIZE << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-LSB: Streaming sets: " << streaming_sets << std::endl;
}