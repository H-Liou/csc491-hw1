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

// SHiP-Lite: 6-bit PC signature per block
uint8_t block_sig[LLC_SETS][LLC_WAYS];

// SHiP outcome table: 4096 entries (6-bit signature), 2 bits/counter
const uint32_t SHIP_SIG_BITS = 6;
const uint32_t SHIP_TABLE_SIZE = 1 << SHIP_SIG_BITS;
uint8_t ship_table[SHIP_TABLE_SIZE]; // 2 bits per entry

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
const uint8_t RRIP_DISTANT = 3;
const uint8_t RRIP_FRIENDLY = 1;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// Helper: hash PC to signature
inline uint8_t GetSignature(uint64_t PC) {
    // Use lower bits of CRC32 for mixing
    return champsim_crc32(PC) & ((1 << SHIP_SIG_BITS) - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(block_sig, 0, sizeof(block_sig));
    memset(ship_table, 1, sizeof(ship_table)); // initialize to weakly friendly
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

    // Standard RRIP victim selection
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

    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);

    // --- Update SHiP outcome table ---
    if (hit) {
        // On hit, increment outcome counter (max 3)
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = RRIP_MRU;
    } else {
        // On miss, decrement outcome counter (min 0) for victim's signature
        uint8_t victim_sig = block_sig[set][way];
        if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;

        // --- Insertion policy ---
        uint8_t ins_rrpv;
        if (ss.streaming && ss.window > 0) {
            // Streaming detected: insert at RRIP_MAX (bypass)
            ins_rrpv = RRIP_MAX;
        } else {
            // Use SHiP outcome table to bias insertion
            if (ship_table[sig] >= 2)
                ins_rrpv = RRIP_FRIENDLY; // cache-friendly PC: insert near-MRU
            else
                ins_rrpv = RRIP_DISTANT;  // cache-polluting PC: insert distant
        }
        rrpv[set][way] = ins_rrpv;
        block_sig[set][way] = sig;
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

    // SHiP outcome table stats
    uint64_t friendly = 0, polluting = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_table[i] >= 2) friendly++;
        else polluting++;
    }
    std::cout << "SHiP-SB: SHiP friendly sigs: " << friendly
              << ", polluting sigs: " << polluting << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count or SHiP table stats
}