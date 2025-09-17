#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Tunable parameters
constexpr int RECENCY_SEG_INIT = 6;  // Initial size of recency segment
constexpr int PRIORITY_SEG_INIT = 10; // Initial size of priority segment
constexpr int RECENCY_MAX = 255;      // Max recency counter
constexpr int FREQ_MAX = 15;          // Max frequency counter
constexpr int ADAPT_INTERVAL = 10000; // How often to adapt segments

struct LineMeta {
    uint8_t recency;    // Recency counter (lower is newer)
    uint8_t freq;       // Frequency counter (LFU)
    uint64_t tag;       // Block tag
    uint64_t last_access;// Timestamp
    bool in_priority;   // Is this block in priority segment?
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;

// Per-set segment sizes and stats
struct SetStats {
    int recency_seg_size = RECENCY_SEG_INIT;
    int priority_seg_size = PRIORITY_SEG_INIT;
    uint64_t hits_recency = 0;
    uint64_t hits_priority = 0;
    uint64_t accesses = 0;
};

std::array<SetStats, LLC_SETS> set_stats;
uint64_t global_timestamp = 0;

// Telemetry
uint64_t total_hits = 0, total_misses = 0;

// Initialize replacement state
void InitReplacementState() {
    for (auto& set : line_meta)
        for (auto& meta : set)
            meta = {RECENCY_MAX, 0, 0, 0, false};
    for (auto& stats : set_stats)
        stats = {RECENCY_SEG_INIT, PRIORITY_SEG_INIT, 0, 0, 0};
    global_timestamp = 0;
    total_hits = total_misses = 0;
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
    global_timestamp++;
    auto& stats = set_stats[set];

    // Adapt segments every ADAPT_INTERVAL accesses
    stats.accesses++;
    if (stats.accesses % ADAPT_INTERVAL == 0) {
        // If priority segment gets more hits, grow it; else, grow recency segment
        if (stats.hits_priority > stats.hits_recency && stats.priority_seg_size < LLC_WAYS - 2) {
            stats.priority_seg_size++;
            stats.recency_seg_size = LLC_WAYS - stats.priority_seg_size;
        } else if (stats.hits_recency > stats.hits_priority && stats.recency_seg_size < LLC_WAYS - 2) {
            stats.recency_seg_size++;
            stats.priority_seg_size = LLC_WAYS - stats.recency_seg_size;
        }
        // Reset stats
        stats.hits_recency = 0;
        stats.hits_priority = 0;
    }

    // Victim selection:
    // - In recency segment: evict LRU (highest recency)
    // - In priority segment: evict lowest frequency, break ties with oldest access

    int victim = -1;
    uint8_t max_recency = 0;
    uint8_t min_freq = FREQ_MAX + 1;
    uint64_t oldest_time = UINT64_MAX;

    // First, try recency segment
    for (int w = 0; w < stats.recency_seg_size; ++w) {
        if (line_meta[set][w].recency > max_recency) {
            max_recency = line_meta[set][w].recency;
            victim = w;
        }
    }
    // If recency segment is full (all recency counters low), fall back to priority segment
    if (victim == -1 || line_meta[set][victim].recency < RECENCY_MAX/2) {
        // Search priority segment
        for (int w = stats.recency_seg_size; w < LLC_WAYS; ++w) {
            const auto& meta = line_meta[set][w];
            if (meta.freq < min_freq || (meta.freq == min_freq && meta.last_access < oldest_time)) {
                min_freq = meta.freq;
                oldest_time = meta.last_access;
                victim = w;
            }
        }
    }
    // Fallback: evict LRU in full set
    if (victim == -1) {
        for (int w = 0; w < LLC_WAYS; ++w) {
            if (line_meta[set][w].recency > max_recency) {
                max_recency = line_meta[set][w].recency;
                victim = w;
            }
        }
    }
    return victim;
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
    global_timestamp++;
    auto& meta = line_meta[set][way];
    auto& stats = set_stats[set];

    // Tag and access timestamp
    meta.tag = paddr >> 6;
    meta.last_access = global_timestamp;

    // Determine which segment this block belongs to
    if (way < stats.recency_seg_size) {
        meta.in_priority = false;
        // Recency segment: update recency counters (move to MRU)
        for (int w = 0; w < stats.recency_seg_size; ++w) {
            if (w == way)
                line_meta[set][w].recency = 0;
            else if (line_meta[set][w].recency < RECENCY_MAX)
                line_meta[set][w].recency++;
        }
        // Reset frequency in recency segment
        meta.freq = hit ? 1 : 0;
        if (hit) stats.hits_recency++;
    } else {
        meta.in_priority = true;
        // Priority segment: update frequency counter
        meta.freq = hit ? std::min<uint8_t>(meta.freq + 1, FREQ_MAX) : 1;
        // Recency counter only lightly updated
        meta.recency = hit ? 0 : RECENCY_MAX/2;
        if (hit) stats.hits_priority++;
    }

    if (hit) total_hits++;
    else total_misses++;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SARDP Policy: Total Hits = " << total_hits
              << ", Total Misses = " << total_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * total_hits / (total_hits + total_misses)) << "%" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[SARDP Heartbeat] Hits: " << total_hits
              << ", Misses: " << total_misses << std::endl;
}