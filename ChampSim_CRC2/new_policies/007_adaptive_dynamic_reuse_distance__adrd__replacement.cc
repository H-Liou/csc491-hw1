#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int REUSE_HISTORY_SIZE = 8;      // Track last N accesses per set
constexpr int REUSE_DIST_THRESHOLD_MIN = 2; // Minimum retention window
constexpr int REUSE_DIST_THRESHOLD_MAX = 64; // Maximum retention window

struct LineState {
    uint64_t tag = 0;
    uint32_t last_access = 0; // Timestamp of last access
};

struct SetState {
    std::vector<LineState> lines;
    std::vector<uint64_t> reuse_history; // Recently accessed line tags
    std::vector<uint32_t> reuse_intervals; // Distance between accesses
    uint32_t timestamp = 0;
    uint32_t reuse_dist_threshold = 8; // Adaptive retention window
    uint64_t hit_count = 0;
    uint64_t miss_count = 0;
};

std::vector<SetState> sets(LLC_SETS);

// Stats
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

void InitReplacementState() {
    for (auto& set : sets) {
        set.lines.resize(LLC_WAYS);
        for (auto& line : set.lines) {
            line.tag = 0;
            line.last_access = 0;
        }
        set.reuse_history.resize(REUSE_HISTORY_SIZE, 0);
        set.reuse_intervals.resize(REUSE_HISTORY_SIZE, REUSE_DIST_THRESHOLD_MAX);
        set.timestamp = 0;
        set.reuse_dist_threshold = 8;
        set.hit_count = 0;
        set.miss_count = 0;
    }
    total_hits = total_misses = total_evictions = 0;
}

// Helper: Find line index by tag
int FindLineByTag(const SetState& set, uint64_t tag) {
    for (int i = 0; i < LLC_WAYS; i++)
        if (set.lines[i].tag == tag)
            return i;
    return -1;
}

// Update reuse history and threshold
void UpdateReuseDistance(SetState& set, uint64_t line_addr) {
    set.timestamp++;
    // Check if line_addr is in history
    int idx = -1;
    for (int i = 0; i < REUSE_HISTORY_SIZE; i++)
        if (set.reuse_history[i] == line_addr)
            idx = i;
    if (idx >= 0) {
        // Compute reuse interval
        uint32_t interval = set.timestamp - set.reuse_intervals[idx];
        set.reuse_intervals[idx] = set.timestamp;
        // Update threshold: average of intervals, clipped to min/max
        uint32_t avg = 0;
        for (int i = 0; i < REUSE_HISTORY_SIZE; i++)
            avg += (set.timestamp - set.reuse_intervals[i]);
        avg = avg / REUSE_HISTORY_SIZE;
        set.reuse_dist_threshold = std::min(std::max(avg, REUSE_DIST_THRESHOLD_MIN), REUSE_DIST_THRESHOLD_MAX);
    } else {
        // Insert into history
        int replace = set.timestamp % REUSE_HISTORY_SIZE;
        set.reuse_history[replace] = line_addr;
        set.reuse_intervals[replace] = set.timestamp;
    }
}

// Find victim: evict line with oldest last_access exceeding threshold, else LRU
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState& s = sets[set];
    uint64_t line_addr = paddr >> 6;
    UpdateReuseDistance(s, line_addr);

    // Prefer to evict lines with last_access older than threshold
    uint32_t oldest_way = 0;
    uint32_t oldest_time = s.timestamp;
    bool found = false;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        uint32_t age = s.timestamp - s.lines[way].last_access;
        if (age > s.reuse_dist_threshold) {
            if (age > oldest_time) {
                oldest_time = age;
                oldest_way = way;
            }
            found = true;
        }
    }
    if (found)
        return oldest_way;

    // Otherwise, fallback to true LRU
    oldest_time = s.timestamp;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.lines[way].last_access < oldest_time) {
            oldest_time = s.lines[way].last_access;
            oldest_way = way;
        }
    }
    return oldest_way;
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
    uint64_t line_addr = paddr >> 6;

    if (hit) { total_hits++; s.hit_count++; }
    else { total_misses++; total_evictions++; s.miss_count++; }

    line.tag = line_addr;
    line.last_access = s.timestamp;
    UpdateReuseDistance(s, line_addr);
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