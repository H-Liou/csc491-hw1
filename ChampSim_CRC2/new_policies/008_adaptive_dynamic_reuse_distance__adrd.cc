#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <cmath>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int MAX_REUSE_DIST = 255; // 8-bit reuse distance
constexpr int PHASE_WINDOW = 64;
constexpr int SPATIAL_NEIGHBORHOOD = 2;
constexpr int STREAMING_THRESHOLD = 40; // % spatial hits

struct LineState {
    uint64_t tag = 0;
    uint8_t reuse_dist = MAX_REUSE_DIST; // Distance since last use
    bool valid = false;
};

struct SetState {
    std::vector<LineState> lines;
    std::vector<uint64_t> recent_addrs;
    uint32_t access_ptr = 0;
    uint32_t spatial_hits = 0;
    uint32_t total_accesses = 0;
    bool streaming_phase = false;
    uint32_t hits = 0;
    uint32_t misses = 0;
};

std::vector<SetState> sets(LLC_SETS);

uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

void InitReplacementState() {
    for (auto& set : sets) {
        set.lines.resize(LLC_WAYS);
        for (auto& line : set.lines) {
            line.tag = 0;
            line.reuse_dist = MAX_REUSE_DIST;
            line.valid = false;
        }
        set.recent_addrs.resize(PHASE_WINDOW, 0);
        set.access_ptr = 0;
        set.spatial_hits = 0;
        set.total_accesses = 0;
        set.streaming_phase = false;
        set.hits = 0;
        set.misses = 0;
    }
    total_hits = total_misses = total_evictions = 0;
}

// Phase detection: streaming/stencil vs irregular
void UpdatePhase(SetState& s, uint64_t paddr) {
    uint64_t line_addr = paddr >> 6;
    bool spatial_hit = false;
    for (int i = 0; i < PHASE_WINDOW; i++) {
        uint64_t prev_addr = s.recent_addrs[i];
        if (prev_addr == 0) continue;
        if (std::abs(int64_t(line_addr) - int64_t(prev_addr)) <= SPATIAL_NEIGHBORHOOD) {
            spatial_hit = true;
            break;
        }
    }
    if (spatial_hit) s.spatial_hits++;
    s.recent_addrs[s.access_ptr] = line_addr;
    s.access_ptr = (s.access_ptr + 1) % PHASE_WINDOW;
    s.total_accesses++;

    // Every PHASE_WINDOW accesses, update streaming phase
    if (s.total_accesses % PHASE_WINDOW == 0) {
        int percent_spatial = (100 * s.spatial_hits) / PHASE_WINDOW;
        s.streaming_phase = (percent_spatial >= STREAMING_THRESHOLD);
        s.spatial_hits = 0;
    }
}

// Victim selection: adaptive reuse distance
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState& s = sets[set];
    UpdatePhase(s, paddr);

    // 1. If streaming phase, evict line with largest reuse distance, prefer non-adjacent
    if (s.streaming_phase) {
        uint64_t line_addr = paddr >> 6;
        uint8_t max_dist = 0;
        uint32_t victim = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            auto& line = s.lines[way];
            if (!line.valid) return way; // Prefer invalid
            int spatial = std::abs(int64_t(line_addr) - int64_t(line.tag));
            uint8_t dist_score = line.reuse_dist + (spatial > SPATIAL_NEIGHBORHOOD ? 32 : 0);
            if (dist_score > max_dist) {
                max_dist = dist_score;
                victim = way;
            }
        }
        return victim;
    }

    // 2. Else, evict line with largest reuse distance (ties: invalid, oldest tag)
    uint8_t max_dist = 0;
    uint32_t victim = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        auto& line = s.lines[way];
        if (!line.valid) return way;
        if (line.reuse_dist > max_dist) {
            max_dist = line.reuse_dist;
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

    if (hit) { total_hits++; s.hits++; }
    else { total_misses++; total_evictions++; s.misses++; }

    uint64_t line_addr = paddr >> 6;

    // Update reuse distances for all lines in set
    for (auto& l : s.lines) {
        if (l.valid && l.tag != line_addr && l.reuse_dist < MAX_REUSE_DIST)
            l.reuse_dist++;
    }

    // On hit: reset reuse distance, mark valid
    if (hit) {
        line.tag = line_addr;
        line.reuse_dist = 0;
        line.valid = true;
    } else {
        // On miss: insert new line, reuse_dist=MAX, valid
        line.tag = line_addr;
        line.reuse_dist = MAX_REUSE_DIST;
        line.valid = true;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ADRD: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}