#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define RRPV_INSERT_MRU 0
#define RRPV_INSERT_DISTANT 3

// SHiP-lite constants
#define SIG_BITS 5
#define SIG_MASK ((1 << SIG_BITS) - 1)
#define OUTCOME_BITS 2
#define OUTCOME_MAX ((1 << OUTCOME_BITS) - 1)
#define OUTCOME_THRESHOLD 1

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3

struct BLOCK_META {
    uint8_t rrpv;         // 2 bits
    uint8_t outcome;      // 2 bits
    uint8_t signature;    // 5 bits
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<BLOCK_META> block_meta;
std::vector<STREAM_DETECTOR> stream_detector;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// SHiP-lite: simple signature hash from PC
inline uint8_t get_signature(uint64_t PC) {
    // Use lower SIG_BITS of CRC32 of PC
    return champsim_crc32(PC) & SIG_MASK;
}

// Streaming detection: updates per access
void update_streaming_detector(uint32_t set, uint64_t curr_addr) {
    STREAM_DETECTOR &sd = stream_detector[set];
    int64_t delta = curr_addr - sd.last_addr;
    if (sd.last_addr != 0) {
        sd.delta_history[sd.ptr] = delta;
        sd.ptr = (sd.ptr + 1) % STREAM_DELTA_HISTORY;
    }
    sd.last_addr = curr_addr;
    // Check monotonicity
    int positive = 0, negative = 0, nonzero = 0;
    for (int i = 0; i < STREAM_DELTA_HISTORY; i++) {
        if (sd.delta_history[i] > 0) positive++;
        else if (sd.delta_history[i] < 0) negative++;
        if (sd.delta_history[i] != 0) nonzero++;
    }
    if (nonzero >= STREAM_DELTA_THRESHOLD &&
        (positive >= STREAM_DELTA_THRESHOLD || negative >= STREAM_DELTA_THRESHOLD)) {
        sd.streaming = true;
    } else {
        sd.streaming = false;
    }
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    stream_detector.resize(LLC_SETS);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = RRPV_MAX;
        block_meta[i].outcome = OUTCOME_MAX / 2;
        block_meta[i].signature = 0;
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
}

// Victim selection: SRRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV_MAX
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv < RRPV_MAX)
            block_meta[idx].rrpv++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX)
            return way;
    }
    // If still none, pick way 0
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
    size_t idx = get_block_meta_idx(set, way);
    BLOCK_META &meta = block_meta[idx];

    // Streaming detection (per set)
    update_streaming_detector(set, paddr);

    // On streaming: bypass fill (do not insert into cache)
    if (stream_detector[set].streaming) {
        meta.rrpv = RRPV_MAX; // mark as least likely reused
        meta.outcome = 0;
        meta.signature = get_signature(PC);
        return;
    }

    // On cache hit
    if (hit) {
        // Promote block to MRU
        meta.rrpv = RRPV_INSERT_MRU;
        // Update outcome counter (saturating)
        if (meta.outcome < OUTCOME_MAX) meta.outcome++;
        return;
    }

    // On miss/fill: use SHiP-lite prediction
    uint8_t sig = get_signature(PC);
    meta.signature = sig;
    // If outcome counter for this block is high, insert at MRU; else distant
    if (meta.outcome > OUTCOME_THRESHOLD)
        meta.rrpv = RRPV_INSERT_MRU;
    else
        meta.rrpv = RRPV_INSERT_DISTANT;
    // Decay outcome counter slightly on miss
    if (meta.outcome > 0) meta.outcome--;
}

// Print end-of-simulation statistics
void PrintStats() {
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "SHiP-Stream: SHiP-lite + Streaming Bypass Hybrid stats\n";
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "SHiP-Stream heartbeat: streaming_sets=" << streaming_sets << "\n";
}