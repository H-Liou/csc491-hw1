#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Dead-block indicator: 2 bits per block
struct BLOCK_META {
    uint8_t dbi;      // 2 bits: dead-block indicator (reuse counter)
    uint8_t rrpv;     // 2 bits: RRIP value
};

// Streaming detector: per set
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<BLOCK_META> block_meta;
std::vector<STREAM_DETECTOR> stream_detector;

// Stats
uint64_t access_counter = 0;
uint64_t streaming_bypass = 0;
uint64_t dbi_hits = 0;
uint64_t dbi_promotes = 0;
uint64_t lip_inserts = 0;
uint64_t decay_events = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
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
        block_meta[i].dbi = 1; // neutral: not dead, not hot
        block_meta[i].rrpv = 3; // RRIP max (LRU)
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
    access_counter = 0;
    streaming_bypass = 0;
    dbi_hits = 0;
    dbi_promotes = 0;
    lip_inserts = 0;
    decay_events = 0;
}

// Victim selection: RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV=3 (LRU)
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv < 3)
            block_meta[idx].rrpv++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
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
    access_counter++;

    size_t idx = get_block_meta_idx(set, way);
    BLOCK_META &meta = block_meta[idx];

    // Streaming detection (per set)
    update_streaming_detector(set, paddr);

    // Periodic DBI decay: every 4096 accesses, halve all counters
    if ((access_counter & 0xFFF) == 0) {
        for (size_t i = 0; i < block_meta.size(); i++) {
            block_meta[i].dbi >>= 1;
        }
        decay_events++;
    }

    // On streaming: bypass fill (do not insert into cache)
    if (!hit && stream_detector[set].streaming) {
        meta.rrpv = 3; // mark as LRU (effectively bypass)
        meta.dbi = 0;  // dead
        streaming_bypass++;
        return;
    }

    // On cache hit
    if (hit) {
        // Promote block to MRU
        meta.rrpv = 0;
        // DBI: increment reuse counter (max saturate)
        if (meta.dbi < 3)
            meta.dbi++;
        dbi_hits++;
        dbi_promotes++;
        return;
    }

    // On miss: insertion
    // If block was dead (dbi==0), insert at LRU (LIP)
    // If block was reused recently (dbi>=2), insert at MRU
    if (meta.dbi == 0) {
        meta.rrpv = 3; // LIP: insert at LRU
        lip_inserts++;
    } else if (meta.dbi >= 2) {
        meta.rrpv = 0; // hot block: insert at MRU
        dbi_promotes++;
    } else {
        meta.rrpv = 2; // neutral: mid-depth
    }
    // Reset DBI on fill
    meta.dbi = 1;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DBI-LIP: Dead-Block Indicator + LIP Insertion + Streaming Bypass\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming bypasses: " << streaming_bypass << "\n";
    std::cout << "DBI hits: " << dbi_hits << "\n";
    std::cout << "DBI MRU promotions: " << dbi_promotes << "\n";
    std::cout << "LIP inserts: " << lip_inserts << "\n";
    std::cout << "DBI decay events: " << decay_events << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DBI-LIP heartbeat: accesses=" << access_counter
              << ", streaming_bypass=" << streaming_bypass
              << ", dbi_hits=" << dbi_hits
              << ", dbi_promotes=" << dbi_promotes
              << ", lip_inserts=" << lip_inserts
              << ", decay_events=" << decay_events << "\n";
}