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
constexpr int FREQ_MAX = 15;      // Saturating frequency counter
constexpr int RECENCY_MAX = 255;  // Recency counter
constexpr int REUSEDIST_MAX = 15; // Saturating reuse distance counter
constexpr int WEIGHT_FREQ = 3;    // Weight for frequency in score
constexpr int WEIGHT_RECENCY = 2; // Weight for recency in score
constexpr int WEIGHT_REUSEDIST = 2; // Weight for reuse distance in score

struct LineMeta {
    uint8_t freq;        // Frequency counter
    uint8_t recency;     // Recency counter
    uint8_t reuse_dist;  // Reuse distance estimator
    uint64_t tag;        // Block tag
    uint64_t last_access;// Global timestamp
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
uint64_t global_timestamp = 0;

// Telemetry
uint64_t total_hits = 0, total_misses = 0;

// Initialize replacement state
void InitReplacementState() {
    for (auto& set : line_meta)
        for (auto& meta : set)
            meta = {0, RECENCY_MAX, REUSEDIST_MAX, 0, 0};
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

    // Composite score: lower is better for eviction
    // Score = WEIGHT_RECENCY * recency - WEIGHT_FREQ * freq + WEIGHT_REUSEDIST * reuse_dist
    // (Higher freq reduces score, higher recency/reuse_dist increases score)
    uint32_t victim = 0;
    int min_score = INT32_MAX;
    uint64_t oldest_time = UINT64_MAX;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        const auto& meta = line_meta[set][w];
        int score = WEIGHT_RECENCY * meta.recency
                  - WEIGHT_FREQ * meta.freq
                  + WEIGHT_REUSEDIST * meta.reuse_dist;
        // Prefer lowest score, break ties with oldest timestamp
        if (score < min_score || (score == min_score && meta.last_access < oldest_time)) {
            min_score = score;
            oldest_time = meta.last_access;
            victim = w;
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

    // Update recency: move to MRU, increment others
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (w == way)
            line_meta[set][w].recency = 0;
        else if (line_meta[set][w].recency < RECENCY_MAX)
            line_meta[set][w].recency++;
    }

    // Update frequency counter
    if (hit) {
        meta.freq = std::min<uint8_t>(meta.freq + 1, FREQ_MAX);
        total_hits++;
    } else {
        meta.freq = 1; // reset to 1 on miss/fill
        total_misses++;
    }

    // Estimate reuse distance: if hit, set to low; if miss, set to high
    if (hit) {
        meta.reuse_dist = std::max<uint8_t>(meta.reuse_dist / 2, 0);
    } else {
        meta.reuse_dist = REUSEDIST_MAX;
    }

    meta.tag = paddr >> 6;
    meta.last_access = global_timestamp;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ADR-FR Policy: Total Hits = " << total_hits
              << ", Total Misses = " << total_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * total_hits / (total_hits + total_misses)) << "%" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[ADR-FR Heartbeat] Hits: " << total_hits
              << ", Misses: " << total_misses << std::endl;
}