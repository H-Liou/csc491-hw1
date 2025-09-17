#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 6-bit PC signature + 2-bit reuse counter per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS];      // 6 bits/block
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS];   // 2 bits/block

// SHiP-lite: 64-entry outcome table (indexed by signature)
uint8_t ship_table[64]; // 2 bits per entry

// Streaming detector: 3 bits/set
struct StreamSet {
    uint64_t last_addr;
    uint8_t stride_count; // up to 3
    uint8_t streaming;    // 1 if streaming detected
    uint8_t window;       // streaming window countdown
};
StreamSet stream_sets[LLC_SETS];

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// Helper: hash PC to 6 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(reuse_ctr, 0, sizeof(reuse_ctr));
    memset(ship_table, 1, sizeof(ship_table)); // Default weakly reused
    memset(stream_sets, 0, sizeof(stream_sets));
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
    // Streaming: if active, always evict block with RRPV==RRIP_MAX
    if (stream_sets[set].streaming && stream_sets[set].window > 0) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        // If none, increment RRPV and retry
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < RRIP_MAX)
                rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        return 0;
    }

    // Dead-block: prefer blocks with reuse_ctr==0 and RRPV==RRIP_MAX
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX && reuse_ctr[set][way] == 0)
            return way;

    // Otherwise, standard RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    // If none, increment RRPV and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] < RRIP_MAX)
            rrpv[set][way]++;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    return 0;
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
    StreamSet &ss = stream_sets[set];
    uint64_t cur_addr = paddr >> 6; // cache line granularity
    int64_t stride = cur_addr - ss.last_addr;
    if (ss.last_addr != 0 && (stride == 1 || stride == -1)) {
        if (ss.stride_count < 3) ss.stride_count++;
        if (ss.stride_count == 3 && !ss.streaming) {
            ss.streaming = 1;
            ss.window = STREAM_WIN;
        }
    } else {
        ss.stride_count = 0;
        ss.streaming = 0;
        ss.window = 0;
    }
    ss.last_addr = cur_addr;
    if (ss.streaming && ss.window > 0)
        ss.window--;

    // --- SHiP-lite signature ---
    uint8_t sig = pc_hash(PC);

    // --- RRIP + SHiP insertion logic ---
    uint8_t ins_rrpv;
    if (ss.streaming && ss.window > 0) {
        // Streaming detected: insert at RRIP_MAX (bypass)
        ins_rrpv = RRIP_MAX;
    } else {
        // Use SHiP table prediction for insertion
        uint8_t pred = ship_table[sig];
        ins_rrpv = (pred >= 2) ? RRIP_MRU : RRIP_DISTANT; // strong reuse: MRU, else distant
    }

    if (hit) {
        rrpv[set][way] = RRIP_MRU;
        // Update reuse counter and SHiP table (positive reinforcement)
        if (reuse_ctr[set][way] < 3) reuse_ctr[set][way]++;
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
    } else {
        // On insertion, set signature and reuse counter
        pc_sig[set][way] = sig;
        reuse_ctr[set][way] = 0;
        rrpv[set][way] = ins_rrpv;
    }

    // --- Dead-block handling in streaming phase ---
    if (ss.streaming && ss.window > 0) {
        // Periodically decay reuse counters to hasten dead block eviction
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (reuse_ctr[set][w] > 0) reuse_ctr[set][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "SHiP-SDB: Streaming sets at end: " << streaming_sets << std::endl;

    // SHiP table summary
    std::cout << "SHiP-SDB: SHiP table (reuse counters): ";
    for (int i = 0; i < 64; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count or SHiP table summary
}