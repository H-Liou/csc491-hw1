#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Tunable parameters
constexpr uint32_t REUSE_COUNTER_MAX = 7;      // Max value for PC reuse counter
constexpr uint32_t SPATIAL_WINDOW = 4;         // # of adjacent lines to consider for spatial locality
constexpr uint32_t PHASE_WINDOW = 128;         // # of accesses to consider for phase detection
constexpr float PHASE_STREAM_THRESHOLD = 0.85; // If miss rate > threshold, treat as streaming

// Replacement state per line
struct LineState {
    uint64_t tag = 0;
    uint64_t last_PC = 0;
    uint8_t reuse_counter = 0; // 0 = low reuse, max = high reuse
    uint8_t spatial_score = 0; // 0 = not spatial, max = highly spatial
    uint64_t last_access = 0;
};

// Per-set state
struct SetState {
    std::vector<LineState> lines;
    uint64_t access_count = 0;
    uint32_t miss_count = 0;
    std::vector<uint32_t> recent_reuse_distances; // For phase detection
};

std::vector<SetState> sets(LLC_SETS);

// Simple PC-based reuse table
std::unordered_map<uint64_t, uint8_t> pc_reuse_table; // PC -> reuse score

// Stats
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

// Initialize replacement state
void InitReplacementState() {
    for (auto& set : sets) {
        set.lines.resize(LLC_WAYS);
        set.access_count = 0;
        set.miss_count = 0;
        set.recent_reuse_distances.clear();
    }
    pc_reuse_table.clear();
    total_hits = total_misses = total_evictions = 0;
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
    SetState& s = sets[set];
    s.access_count++;

    // Phase detection: calculate miss rate over window
    float miss_rate = (s.access_count > PHASE_WINDOW) ? 
        float(s.miss_count) / float(s.access_count) : 0.0f;

    bool streaming_phase = (miss_rate > PHASE_STREAM_THRESHOLD);

    // Score each line: blend reuse, spatial, phase
    uint32_t victim = 0;
    int min_score = 1e9;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        LineState& line = s.lines[way];

        // PC-based reuse prediction
        uint8_t pc_reuse = pc_reuse_table[line.last_PC];

        // Spatial locality: check if line addr is close to current paddr
        uint8_t spatial = (std::abs(int64_t(line.tag) - int64_t(paddr >> 6)) <= SPATIAL_WINDOW) ? 1 : 0;

        // Age: older lines are more likely to be evicted
        uint64_t age = s.access_count - line.last_access;

        // Composite score: lower is more likely to be evicted
        int score = 0;
        if (streaming_phase) {
            // In streaming, evict oldest line (age dominates)
            score = int(age) - int(pc_reuse)*2 - int(spatial)*2;
        } else {
            // In reuse phase, favor high reuse and spatial lines
            score = int(age) + (REUSE_COUNTER_MAX - int(pc_reuse))*3 + (1 - int(spatial))*2;
        }

        if (score < min_score) {
            min_score = score;
            victim = way;
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
    SetState& s = sets[set];
    LineState& line = s.lines[way];

    if (hit) total_hits++; else { total_misses++; s.miss_count++; }

    // Update line metadata
    line.tag = paddr >> 6;
    line.last_PC = PC;
    line.last_access = s.access_count;

    // Update PC-based reuse table
    auto& reuse = pc_reuse_table[PC];
    if (hit) {
        if (reuse < REUSE_COUNTER_MAX) reuse++;
    } else {
        if (reuse > 0) reuse--;
    }
    line.reuse_counter = reuse;

    // Spatial score: check if previous access was spatially close
    if (way > 0 && std::abs(int64_t(line.tag) - int64_t(s.lines[way-1].tag)) <= SPATIAL_WINDOW)
        line.spatial_score = std::min(uint8_t(line.spatial_score+1), uint8_t(3));
    else
        line.spatial_score = 0;

    // Track reuse distance for phase detection
    if (hit) {
        s.recent_reuse_distances.push_back(s.access_count - line.last_access);
        if (s.recent_reuse_distances.size() > PHASE_WINDOW)
            s.recent_reuse_distances.erase(s.recent_reuse_distances.begin());
    }

    // Track evictions
    if (!hit) total_evictions++;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ARPP: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}