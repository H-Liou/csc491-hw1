#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Per-block metadata: RRIP, PC signature, reuse counter
struct SLDAS_BlockMeta {
    uint8_t rrpv;       // 2 bits
    uint8_t pc_sig;     // 6 bits
    uint8_t reuse;      // 2 bits dead-block counter
};
SLDAS_BlockMeta block_meta[LLC_SETS][LLC_WAYS];

// SHiP-lite outcome table: 4096 entries, 2 bits each
uint8_t ship_table[4096];

// Streaming detector: 3 bits/set
struct SLDAS_StreamSet {
    uint64_t last_addr;
    uint8_t stride_count; // up to 3
    uint8_t streaming;    // 1 if streaming detected
    uint8_t window;       // streaming window countdown
};
SLDAS_StreamSet stream_sets[LLC_SETS];

// Helper: get 6-bit PC signature
inline uint8_t get_pc_sig(uint64_t PC) {
    return (PC >> 2) & 0x3F;
}
inline uint16_t get_ship_idx(uint8_t sig) {
    return sig;
}

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// Reuse counter decay interval
const uint64_t DECAY_INTERVAL = 500000;  // every 500K accesses

// Stats for periodic decay
uint64_t access_counter = 0;

// Initialize replacement state
void InitReplacementState() {
    memset(block_meta, 0, sizeof(block_meta));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reusable
    memset(stream_sets, 0, sizeof(stream_sets));
    access_counter = 0;
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
    // Streaming: if active, always evict LRU (highest RRPV)
    if (stream_sets[set].streaming && stream_sets[set].window > 0) {
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

    // Dead-block first: look for lines with reuse==0 and RRPV==RRIP_MAX
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (block_meta[set][way].reuse == 0 && block_meta[set][way].rrpv == RRIP_MAX)
            return way;
    }
    // If none, pick the line with RRPV==RRIP_MAX
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (block_meta[set][way].rrpv == RRIP_MAX)
            return way;
    }
    // If still none, increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (block_meta[set][way].rrpv < RRIP_MAX)
            block_meta[set][way].rrpv++;
    // Retry after increment
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (block_meta[set][way].reuse == 0 && block_meta[set][way].rrpv == RRIP_MAX)
            return way;
    }
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (block_meta[set][way].rrpv == RRIP_MAX)
            return way;
    }
    // Fallback: way 0
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
    access_counter++;

    // --- Streaming detector ---
    SLDAS_StreamSet &ss = stream_sets[set];
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
    uint8_t pc_sig = get_pc_sig(PC);
    uint16_t sig_idx = get_ship_idx(pc_sig);

    // --- Dead-block counter decay (periodic) ---
    if ((access_counter % DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (block_meta[s][w].reuse > 0)
                    block_meta[s][w].reuse--;
    }

    // --- On hit ---
    if (hit) {
        block_meta[set][way].rrpv = RRIP_MRU;
        block_meta[set][way].reuse = (block_meta[set][way].reuse < 3) ? block_meta[set][way].reuse + 1 : 3;
        // Strengthen SHiP outcome
        if (ship_table[sig_idx] < 3)
            ship_table[sig_idx]++;
    }
    // --- On miss (new insertion) ---
    else {
        // Weaken SHiP outcome on miss/eviction
        if (ship_table[sig_idx] > 0)
            ship_table[sig_idx]--;

        // Insert new block
        block_meta[set][way].pc_sig = pc_sig;

        // Streaming: bypass (insert as LRU, dead)
        if (ss.streaming && ss.window > 0) {
            block_meta[set][way].rrpv = RRIP_MAX;
            block_meta[set][way].reuse = 0;
        } else {
            // SHiP-guided insertion
            if (ship_table[sig_idx] >= 2) {
                block_meta[set][way].rrpv = RRIP_MRU;
                block_meta[set][way].reuse = 2; // likely reusable
            }
            else {
                block_meta[set][way].rrpv = RRIP_DISTANT;
                block_meta[set][way].reuse = 1; // less likely reusable
            }
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "SLDAS: Streaming sets at end: " << streaming_sets << std::endl;

    // Dead block fraction
    uint64_t dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (block_meta[s][w].reuse == 0)
                dead_blocks++;
            total_blocks++;
        }
    std::cout << "SLDAS: Fraction of dead blocks at end: " << (double(dead_blocks) / total_blocks) << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming window stats or dead block ratio
}