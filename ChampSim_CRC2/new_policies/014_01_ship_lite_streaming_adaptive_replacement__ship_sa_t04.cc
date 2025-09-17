#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit PC signature per line, 2-bit outcome counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024 // 1K entries: 6 bits index, 2 bits counter = 2.5 KiB

struct SHIPEntry {
    uint8_t reuse_ctr; // 2 bits
};
SHIPEntry ship_table[SHIP_SIG_ENTRIES];

// Per-line metadata: signature
uint8_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits/block

// RRIP: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set, last addr/delta, 1-bit flag, 3-bit confidence
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_flag[LLC_SETS]; // 1 bit/set
uint8_t stream_conf[LLC_SETS];    // 3 bits/set

// Helper: get SHIP signature from PC
inline uint8_t GetSignature(uint64_t PC) {
    // Simple hash: lower 6 bits XOR upper 6 bits
    return ((PC >> 2) ^ (PC >> 8)) & ((1 << SHIP_SIG_BITS) - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU on reset
    memset(line_sig, 0, sizeof(line_sig));
    memset(ship_table, 0, sizeof(ship_table));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(stream_conf, 0, sizeof(stream_conf));
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
    // Streaming: prefer bypass (do not insert, victim is invalid)
    if (streaming_flag[set]) {
        // Find invalid block first
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        // Otherwise, pick block with RRPV==3
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment RRPV until found
        while (true) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] == 3)
                    return way;
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] < 3)
                    rrpv[set][way]++;
        }
    }

    // RRIP fallback: pick block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
    // Increment RRPV until found
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
    // --- Streaming detector update ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_conf[set] < 7) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    last_addr[set] = paddr;
    last_delta[set] = delta;
    streaming_flag[set] = (stream_conf[set] >= 5) ? 1 : 0;

    // --- SHIP signature ---
    uint8_t sig = GetSignature(PC);

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Update SHIP outcome: increment counter (max 3)
        if (ship_table[line_sig[set][way]].reuse_ctr < 3)
            ship_table[line_sig[set][way]].reuse_ctr++;
        return;
    }

    // --- On cache miss or fill ---
    uint8_t ins_rrpv = 3; // default LRU

    // Streaming: insert at distant RRPV or bypass (simulate bypass by LRU)
    if (streaming_flag[set]) {
        ins_rrpv = 3;
    }
    // SHIP: use outcome counter to bias insertion
    else {
        uint8_t ctr = ship_table[sig].reuse_ctr;
        if (ctr >= 2) {
            ins_rrpv = 0; // high reuse: insert at MRU
        } else if (ctr == 1) {
            ins_rrpv = 2; // moderate reuse: mid
        } else {
            ins_rrpv = 3; // low reuse: insert at LRU
        }
    }

    // Update block metadata
    rrpv[set][way] = ins_rrpv;
    line_sig[set][way] = sig;

    // On eviction without reuse, decrement SHIP counter (min 0)
    if (!hit && rrpv[set][way] == 3) {
        uint8_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_ctr > 0)
            ship_table[evict_sig].reuse_ctr--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s])
            streaming_sets++;
    std::cout << "SHiP-SA: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // SHIP counter histogram
    uint64_t ship_hist[4] = {0};
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        ship_hist[ship_table[i].reuse_ctr]++;
    std::cout << "SHiP-SA: SHIP outcome counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed for SHIP counters (already saturating)
    // Optionally, decay streaming confidence for sets (to avoid stuck streaming)
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_conf[s] > 0)
            stream_conf[s]--;
}