#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//--------------------------------------------
// SHiP-lite metadata: 4-bit PC signature, 2-bit reuse counter
#define SHIP_SIG_BITS 4
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS) // 16
uint8_t ship_reuse[LLC_SETS][SHIP_TABLE_SIZE]; // 2 bits per signature per set

// Per-block SHiP signature for promotion on hit
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 4 bits per block

// RRIP bits: 2 per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Streaming detector: 2 bits per set, last address per set
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set
uint64_t last_addr[LLC_SETS];

// Streaming threshold
#define STREAM_THRESHOLD 3

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Distant for all blocks
    memset(ship_reuse, 1, sizeof(ship_reuse)); // Start at weak reuse
    memset(block_sig, 0, sizeof(block_sig));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
}

//--------------------------------------------
// Streaming detector update
inline void update_streaming(uint32_t set, uint64_t paddr) {
    uint64_t last = last_addr[set];
    uint64_t delta = (last == 0) ? 0 : (paddr > last ? paddr - last : last - paddr);
    if (last != 0 && (delta == 64 || delta == 128)) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_addr[set] = paddr;
}

//--------------------------------------------
// Find victim in the set (RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if streaming detected, always evict block with rrpv==3
    if (stream_ctr[set] >= STREAM_THRESHOLD) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
        // Try again
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
    }

    // Normal RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
    return 0; // Should not reach
}

//--------------------------------------------
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
    //--- Streaming detector update
    update_streaming(set, paddr);

    //--- SHiP-lite signature
    uint8_t sig = ((PC >> 2) ^ set) & SHIP_SIG_MASK;

    //--- Streaming bypass: If streaming detected, do not insert, just mark as distant
    if (stream_ctr[set] >= STREAM_THRESHOLD) {
        rrpv[set][way] = 3;
        block_sig[set][way] = sig;
        return;
    }

    //--- SHiP insertion logic: Use signature prediction
    uint8_t reuse_ctr = ship_reuse[set][sig];
    uint8_t ins_rrpv = 3; // Default: long re-reference (distant)

    if (reuse_ctr >= 2)
        ins_rrpv = 1; // Short re-reference (likely reused soon)
    else if (reuse_ctr == 1)
        ins_rrpv = 2; // Medium
    // else ins_rrpv = 3; // Dead or streaming

    // On hit: promote & reinforce signature
    if (hit) {
        rrpv[set][way] = 0;
        // Reinforce signature reuse
        uint8_t sig_hit = block_sig[set][way];
        if (ship_reuse[set][sig_hit] < 3)
            ship_reuse[set][sig_hit]++;
    } else {
        rrpv[set][way] = ins_rrpv;
        block_sig[set][way] = sig;
        // If block replaced, penalize old signature
        uint8_t victim_sig = block_sig[set][way];
        if (ship_reuse[set][victim_sig] > 0)
            ship_reuse[set][victim_sig]--;
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-lite + Streaming-Bypass Hybrid: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= STREAM_THRESHOLD)
            streaming_sets++;
    std::cout << "Sets with streaming detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count
}