#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Policy parameters ---
constexpr int HOT_REGION_SIZE = 6;      // Number of "hot" ways per set
constexpr int PHASE_WINDOW = 128;       // Window for phase detection
constexpr double REGULAR_PHASE_THRESHOLD = 0.55; // Hit ratio threshold for regular phase

struct LineMeta {
    uint8_t lru;         // LRU stack position (0=MRU, LLC_WAYS-1=LRU)
    bool is_hot;         // True if in hot region
    uint64_t tag;        // Block tag
    uint64_t last_access;// Timestamp for stats/debug
};

struct SetPhase {
    uint32_t hits;
    uint32_t accesses;
    bool regular_phase; // True if spatial locality detected
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetPhase, LLC_SETS> set_phase;
uint64_t global_timestamp = 0;

// Telemetry
uint64_t total_hits = 0, total_misses = 0;

// Initialize replacement state
void InitReplacementState() {
    for (auto& set : line_meta)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            set[w] = {static_cast<uint8_t>(w), false, 0, 0};
    for (auto& sp : set_phase)
        sp = {0, 0, false};
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
    // Phase detection: regular or irregular?
    auto& phase = set_phase[set];
    bool regular = phase.regular_phase;

    // Eviction priority:
    // - In regular phase: only evict from cold region (ways HOT_REGION_SIZE...LLC_WAYS-1)
    // - In irregular phase: evict true LRU (highest lru value), hot/cold ignored

    uint32_t victim = 0;
    uint8_t max_lru = 0;
    if (regular) {
        // Only evict from cold region
        max_lru = 0;
        for (uint32_t w = HOT_REGION_SIZE; w < LLC_WAYS; ++w) {
            if (line_meta[set][w].lru >= max_lru) {
                max_lru = line_meta[set][w].lru;
                victim = w;
            }
        }
    } else {
        // Evict true LRU in the set
        max_lru = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (line_meta[set][w].lru >= max_lru) {
                max_lru = line_meta[set][w].lru;
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

    // Update per-set stats for phase detection
    auto& phase = set_phase[set];
    phase.accesses++;
    if (hit) {
        phase.hits++;
        total_hits++;
    } else {
        total_misses++;
    }

    // Every PHASE_WINDOW accesses, update phase
    if (phase.accesses % PHASE_WINDOW == 0) {
        double hit_ratio = static_cast<double>(phase.hits) / phase.accesses;
        phase.regular_phase = (hit_ratio > REGULAR_PHASE_THRESHOLD);
        // Reset window
        phase.hits = 0;
        phase.accesses = 0;
    }

    // Update LRU stack
    uint8_t touched_lru = line_meta[set][way].lru;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (line_meta[set][w].lru < touched_lru)
            line_meta[set][w].lru++;
    }
    line_meta[set][way].lru = 0;

    // Update hot/cold region
    // After every access, re-sort LRU stack and mark top HOT_REGION_SIZE as hot
    std::array<uint8_t, LLC_WAYS> lru_order;
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        lru_order[w] = line_meta[set][w].lru;
    // Find HOT_REGION_SIZE smallest lru values
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        line_meta[set][w].is_hot = (line_meta[set][w].lru < HOT_REGION_SIZE);

    // Update tag and timestamp
    line_meta[set][way].tag = paddr >> 6;
    line_meta[set][way].last_access = global_timestamp;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "PA-DSLRU Policy: Total Hits = " << total_hits
              << ", Total Misses = " << total_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * total_hits / (total_hits + total_misses)) << "%" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[PA-DSLRU Heartbeat] Hits: " << total_hits
              << ", Misses: " << total_misses << std::endl;
}