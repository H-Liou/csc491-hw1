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

// SHiP-lite: 4-bit PC signatures per block, 2-bit outcome counter per signature
const uint32_t SHIP_SIG_BITS = 4;
const uint32_t SHIP_SIG_ENTRIES = 4096; // 4K entries, 4 bits each
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 4 bits per block
uint8_t ship_table[SHIP_SIG_ENTRIES];  // 2 bits per signature

// Streaming detector: 3 bits/set
struct StreamSet {
    uint64_t last_addr;
    uint8_t stride_count; // up to 3
    uint8_t streaming;    // 1 if streaming detected
    uint8_t window;       // streaming window countdown
};
StreamSet stream_sets[LLC_SETS];

const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;
const uint8_t STREAM_WIN = 8;

// Helper: hash PC to SHiP signature table index
inline uint16_t ship_sig_idx(uint64_t PC) {
    // 4 bits: simple xor-mix and mask
    return ((PC >> 2) ^ (PC >> 6) ^ (PC >> 12)) & (SHIP_SIG_ENTRIES - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(block_sig, 0, sizeof(block_sig));
    memset(ship_table, 1, sizeof(ship_table)); // default neutral outcome
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
    // Streaming: evict block with RRPV==RRIP_MAX
    if (stream_sets[set].streaming && stream_sets[set].window > 0) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < RRIP_MAX)
                rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        return 0;
    }
    // Standard RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
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

    // --- SHiP-lite outcome ---
    uint16_t sig_idx = ship_sig_idx(PC);
    if (hit) {
        // On hit, promote block and increment outcome counter (max 3)
        rrpv[set][way] = RRIP_MRU;
        if (ship_table[sig_idx] < 3)
            ship_table[sig_idx]++;
    } else {
        // On miss, insert with bias:
        uint8_t ins_rrpv;
        if (stream_sets[set].streaming && stream_sets[set].window > 0) {
            // Streaming: insert at RRIP_MAX (bypass)
            ins_rrpv = RRIP_MAX;
        } else {
            // Use SHiP outcome: reuse history
            if (ship_table[sig_idx] >= 2)
                ins_rrpv = RRIP_DISTANT; // moderate retention
            else
                ins_rrpv = RRIP_MAX; // rarely reused, insert distant
        }
        rrpv[set][way] = ins_rrpv;
        // Tag block with signature
        block_sig[set][way] = PC & 0xF;
        // On victim eviction (if not hit), decay outcome
        uint16_t victim_sig = block_sig[set][way];
        if (!hit && ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "SHiP-SB: Streaming sets at end: " << streaming_sets << std::endl;
    // SHiP outcome histogram
    uint64_t good = 0, poor = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_table[i] >= 2) good++;
        else poor++;
    }
    std::cout << "SHiP-SB: SHiP signatures reused: " << good << ", not reused: " << poor << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count or SHiP signature stats
}