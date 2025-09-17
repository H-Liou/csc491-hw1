#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 2048 // 2 KiB: 2048 x 2 bits
uint8_t ship_table[SHIP_TABLE_SIZE]; // 2-bit outcome counter per signature

// Per-block PC signature (6 bits per block)
uint8_t block_sig[LLC_SETS][LLC_WAYS];

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector: per-set, last addr/delta, 2-bit streaming counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// Helper: compute SHiP signature (6 bits from PC)
inline uint16_t GetSignature(uint64_t PC) {
    // Use CRC or simple hash
    return champsim_crc2(PC) & ((1 << SHIP_SIG_BITS) - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(ship_table, 1, sizeof(ship_table)); // weakly reusable
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // distant
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
}

// Streaming detector (called on every access/fill)
void UpdateStreamingDetector(uint32_t set, uint64_t paddr) {
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
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
    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
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
    uint16_t sig = GetSignature(PC);

    // --- On hit: promote to MRU, update SHiP outcome ---
    if (hit) {
        rrpv[set][way] = 0;
        // Strengthen SHiP counter for this signature
        if (ship_table[sig] < 3) ship_table[sig]++;
        return;
    }

    // --- On miss/fill: decide insertion depth ---
    uint8_t ins_rrpv = 2; // default

    // Streaming: if streaming detected, bypass or insert at distant RRPV
    if (stream_ctr[set] >= 2) {
        ins_rrpv = 3; // bypass (insert at distant, evict soon)
    } else {
        // SHiP: if signature is "good", insert at MRU; else at distant
        if (ship_table[sig] >= 2)
            ins_rrpv = 0; // MRU
        else
            ins_rrpv = 3; // distant
    }

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP outcome for victim block ---
    // Only if victim block was dead (not reused)
    uint16_t victim_sig = block_sig[set][way];
    if (!hit && victim_sig < SHIP_TABLE_SIZE) {
        // If block was not promoted to MRU since insertion, weaken SHiP counter
        if (rrpv[set][way] == 3 && ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming counter histogram
    uint64_t stream_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        stream_hist[stream_ctr[s]]++;
    std::cout << "SHiP-SA: Streaming counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << stream_hist[i] << " ";
    std::cout << std::endl;

    // SHiP table histogram
    uint64_t ship_hist[4] = {0};
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        ship_hist[ship_table[i]]++;
    std::cout << "SHiP-SA: SHiP counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age streaming counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] > 0)
            stream_ctr[s]--;
}