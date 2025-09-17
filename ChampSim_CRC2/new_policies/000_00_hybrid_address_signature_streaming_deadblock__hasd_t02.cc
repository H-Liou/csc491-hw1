#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Replacement metadata
struct HASD_BlockMeta {
    uint8_t rrpv;           // 2 bits: RRIP value
    uint8_t addr_sig;       // 6 bits: address signature
    uint8_t dead_ctr;       // 2 bits: dead-block counter
};

HASD_BlockMeta block_meta[LLC_SETS][LLC_WAYS];

// Address signature outcome table: 2048 entries, 2 bits each
uint8_t addr_sig_table[2048];

// Streaming detector: 3 bits per set
struct HASD_StreamSet {
    uint64_t last_addr;
    uint8_t stride_count;   // up to 3
    uint8_t streaming;      // 1 if streaming detected, else 0
    uint8_t window;         // streaming window countdown
};
HASD_StreamSet stream_sets[LLC_SETS];

// Helper: get 6-bit address signature
inline uint8_t get_addr_sig(uint64_t paddr) {
    // Use bits [12:17] of paddr (cache line granularity)
    return (paddr >> 12) & 0x3F;
}

// Helper: get index into addr_sig_table
inline uint16_t get_sig_idx(uint8_t sig) {
    return sig;
}

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// Dead-block constants
const uint8_t DEAD_MAX = 3;
const uint8_t DEAD_MIN = 0;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// Initialize replacement state
void InitReplacementState() {
    memset(block_meta, 0, sizeof(block_meta));
    memset(addr_sig_table, 1, sizeof(addr_sig_table)); // weakly reusable
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
    // Streaming bypass: if set is streaming, bypass (return invalid way)
    if (stream_sets[set].streaming && stream_sets[set].window > 0) {
        // Find LRU (highest RRPV)
        uint32_t lru_way = 0;
        uint8_t max_rrpv = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (block_meta[set][way].rrpv >= max_rrpv) {
                max_rrpv = block_meta[set][way].rrpv;
                lru_way = way;
            }
        }
        return lru_way;
    }

    // Normal RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (block_meta[set][way].rrpv == RRIP_MAX)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (block_meta[set][way].rrpv < RRIP_MAX)
                block_meta[set][way].rrpv++;
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
    // --- Streaming detector ---
    HASD_StreamSet &ss = stream_sets[set];
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

    // --- Address signature ---
    uint8_t addr_sig = get_addr_sig(paddr);
    uint16_t sig_idx = get_sig_idx(addr_sig);

    // --- Dead-block counter decay (every 1024 accesses) ---
    static uint64_t access_counter = 0;
    access_counter++;
    if ((access_counter & 0x3FF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (block_meta[s][w].dead_ctr > DEAD_MIN)
                    block_meta[s][w].dead_ctr--;
        // Decay addr_sig_table
        for (uint32_t i = 0; i < 2048; ++i)
            if (addr_sig_table[i] > 0)
                addr_sig_table[i]--;
    }

    // --- On hit ---
    if (hit) {
        block_meta[set][way].rrpv = RRIP_MRU;
        // Mark block as live
        if (block_meta[set][way].dead_ctr > DEAD_MIN)
            block_meta[set][way].dead_ctr--;
        // Strengthen signature outcome
        if (addr_sig_table[sig_idx] < 3)
            addr_sig_table[sig_idx]++;
    }
    // --- On miss (new insertion) ---
    else {
        // Dead-block counter: increment if block was not reused before eviction
        if (block_meta[set][way].dead_ctr < DEAD_MAX)
            block_meta[set][way].dead_ctr++;
        // Weaken signature outcome if block was dead
        if (addr_sig_table[sig_idx] > 0)
            addr_sig_table[sig_idx]--;

        // Insert new block
        block_meta[set][way].addr_sig = addr_sig;
        // Streaming: bypass (insert as LRU)
        if (ss.streaming && ss.window > 0) {
            block_meta[set][way].rrpv = RRIP_MAX;
        } else {
            // If signature is hot and dead_ctr is low, insert at MRU
            if (addr_sig_table[sig_idx] >= 2 && block_meta[set][way].dead_ctr <= 1)
                block_meta[set][way].rrpv = RRIP_MRU;
            else
                block_meta[set][way].rrpv = RRIP_DISTANT;
        }
        // Reset dead_ctr for new block
        block_meta[set][way].dead_ctr = DEAD_MIN;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Optionally print dead-block distribution, streaming events, etc.
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "HASD: Streaming sets at end: " << streaming_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming window stats
}