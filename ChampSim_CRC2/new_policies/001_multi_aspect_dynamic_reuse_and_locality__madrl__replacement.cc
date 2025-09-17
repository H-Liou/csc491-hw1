#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <array>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Tunable parameters
constexpr int PC_REUSE_TABLE_SIZE = 4096;
constexpr int SPATIAL_RADIUS = 3; // Number of neighbor blocks for spatial locality
constexpr int RECENCY_MAX = 255;  // Max recency counter
constexpr int WEIGHT_RECENCY = 2; // Weight for recency in score
constexpr int WEIGHT_REUSE   = 3; // Weight for reuse in score
constexpr int WEIGHT_SPATIAL = 1; // Weight for spatial in score

// Replacement state structures
struct LineMeta {
    uint8_t recency;       // LRU-style recency
    uint8_t pc_reuse;      // PC-based reuse score
    uint8_t spatial_score; // Spatial locality score
    uint64_t tag;          // Block tag
    uint64_t last_access;  // Global timestamp
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
uint64_t global_timestamp = 0;

// PC-based reuse predictor (simple saturating counter per PC)
struct PCEntry {
    uint8_t reuse_counter;
    uint64_t last_used;
};
std::unordered_map<uint64_t, PCEntry> pc_reuse_table;

// Telemetry
uint64_t total_hits = 0, total_misses = 0;

// Initialize replacement state
void InitReplacementState() {
    for (auto& set : line_meta)
        for (auto& meta : set)
            meta = {RECENCY_MAX, 0, 0, 0, 0};
    pc_reuse_table.clear();
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

    // Update spatial scores for all lines in the set
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        uint8_t score = 0;
        uint64_t addr = current_set[w].address;
        if (addr == 0) {
            line_meta[set][w].spatial_score = 0;
            continue;
        }
        for (uint32_t k = 1; k <= SPATIAL_RADIUS; ++k) {
            for (uint32_t w2 = 0; w2 < LLC_WAYS; ++w2) {
                if (w2 == w) continue;
                uint64_t neighbor_addr = current_set[w2].address;
                if (neighbor_addr == 0) continue;
                if (std::abs((int64_t)neighbor_addr - (int64_t)addr) <= k * 64)
                    score++;
            }
        }
        line_meta[set][w].spatial_score = score;
    }

    // Get PC reuse score for this access
    uint8_t pc_reuse_score = 0;
    auto pc_it = pc_reuse_table.find(PC);
    if (pc_it != pc_reuse_table.end())
        pc_reuse_score = pc_it->second.reuse_counter;

    // Composite score: lower is better for eviction
    // Score = WEIGHT_RECENCY * recency + WEIGHT_REUSE * pc_reuse + WEIGHT_SPATIAL * spatial
    uint32_t victim = 0;
    uint32_t min_score = UINT32_MAX;
    uint64_t oldest_time = UINT64_MAX;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        const auto& meta = line_meta[set][w];
        uint32_t score = WEIGHT_RECENCY * meta.recency +
                         WEIGHT_REUSE   * meta.pc_reuse +
                         WEIGHT_SPATIAL * meta.spatial_score;
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

    // Update recency (move to MRU, increment others)
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (w == way)
            line_meta[set][w].recency = 0;
        else if (line_meta[set][w].recency < RECENCY_MAX)
            line_meta[set][w].recency++;
    }

    // Update PC reuse predictor
    auto& entry = pc_reuse_table[PC];
    if (hit) {
        entry.reuse_counter = std::min<uint8_t>(entry.reuse_counter + 1, 15);
        total_hits++;
    } else {
        entry.reuse_counter = std::max<uint8_t>(entry.reuse_counter, 1);
        total_misses++;
    }
    entry.last_used = global_timestamp;
    if (pc_reuse_table.size() > PC_REUSE_TABLE_SIZE) {
        // Simple LRU eviction for PC table
        uint64_t oldest = UINT64_MAX;
        uint64_t oldest_pc = 0;
        for (const auto& kv : pc_reuse_table) {
            if (kv.second.last_used < oldest) {
                oldest = kv.second.last_used;
                oldest_pc = kv.first;
            }
        }
        pc_reuse_table.erase(oldest_pc);
    }

    // Update line meta
    meta.pc_reuse = entry.reuse_counter;
    meta.tag = paddr >> 6;
    meta.last_access = global_timestamp;
    // spatial_score will be updated in GetVictimInSet

    // No need to update spatial_score here; it's recomputed on victim selection
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "MADRL Policy: Total Hits = " << total_hits
              << ", Total Misses = " << total_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * total_hits / (total_hits + total_misses)) << "%" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[MADRL Heartbeat] Hits: " << total_hits
              << ", Misses: " << total_misses << std::endl;
}