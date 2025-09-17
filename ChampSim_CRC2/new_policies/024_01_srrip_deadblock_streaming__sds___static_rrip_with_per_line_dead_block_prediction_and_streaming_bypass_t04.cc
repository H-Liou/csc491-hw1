#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP: 2-bit RRPV per block
struct BlockMeta {
    uint8_t rrpv;       // 2 bits
    uint8_t reuse_ctr;  // 2 bits: dead-block predictor
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Streaming detector: last address, last delta, 2-bit confidence per set
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_conf; // 2 bits
};
StreamDetect stream_meta[LLC_SETS];

// Periodic decay counter
uint64_t access_count = 0;
const uint64_t DECAY_PERIOD = 1000000; // Decay every 1M accesses

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(stream_meta, 0, sizeof(stream_meta));
    access_count = 0;
}

// Streaming detector: returns true if stream detected in this set
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_meta[set];
    int64_t delta = paddr - sd.last_addr;
    bool is_stream = false;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_conf < 3) sd.stream_conf++;
        } else {
            if (sd.stream_conf > 0) sd.stream_conf--;
        }
        if (sd.stream_conf >= 2) is_stream = true;
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return is_stream;
}

// Find victim in the set (prefer invalid, else RRPV==3, else dead-block, else increment RRPV)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Prefer blocks predicted dead (reuse_ctr==0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (meta[set][way].reuse_ctr == 0)
            return way;
    // SRRIP: prefer RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
                meta[set][way].rrpv++;
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
    access_count++;

    // --- Streaming detector ---
    bool is_stream = IsStreaming(set, paddr);

    // --- Dead-block predictor: update reuse counter ---
    if (hit) {
        meta[set][way].reuse_ctr = (meta[set][way].reuse_ctr < 3) ? meta[set][way].reuse_ctr + 1 : 3;
        meta[set][way].rrpv = 0; // Promote to MRU
        return;
    } else {
        // On fill/miss: if streaming, bypass (do not insert); else insert at distant or near based on dead-block prediction
        if (is_stream) {
            // Streaming: bypass if possible (simulate by setting RRPV=3 and reuse_ctr=0)
            meta[set][way].rrpv = 3;
            meta[set][way].reuse_ctr = 0;
        } else {
            // Dead-block: if victim reuse_ctr==0, insert at RRPV=2 (more likely to be reused); else RRPV=3
            uint8_t victim_reuse = meta[set][way].reuse_ctr;
            if (victim_reuse == 0)
                meta[set][way].rrpv = 2;
            else
                meta[set][way].rrpv = 3;
            meta[set][way].reuse_ctr = 1; // weakly dead by default
        }
    }

    // --- Decay reuse counters periodically ---
    if (access_count % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (meta[s][w].reuse_ctr > 0)
                    meta[s][w].reuse_ctr--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t stream_sets = 0, dead_blocks = 0, reused_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].stream_conf >= 2) stream_sets++;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (meta[s][w].reuse_ctr == 0) dead_blocks++;
            if (meta[s][w].reuse_ctr >= 2) reused_blocks++;
        }
    std::cout << "SDS: streaming sets=" << stream_sets << "/" << LLC_SETS
              << ", dead blocks=" << dead_blocks << "/" << (LLC_SETS*LLC_WAYS)
              << ", reused blocks=" << reused_blocks << "/" << (LLC_SETS*LLC_WAYS)
              << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed; handled in UpdateReplacementState
}