#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int PC_REUSE_MAX = 7;
constexpr int PC_REUSE_MIN = 0;
constexpr int STRIDE_WINDOW = 32;
constexpr int SPATIAL_THRESHOLD = 24; // If >=24/32 accesses have same stride, treat as spatial

struct LineState {
    uint64_t tag = 0;
    uint64_t last_PC = 0;
    uint64_t last_access = 0;
    uint8_t lru_stack = 0;
};

struct SetState {
    std::vector<LineState> lines;
    std::vector<int64_t> strides; // recent access strides
    uint64_t last_addr = 0;
    uint32_t stride_ptr = 0;
    uint32_t spatial_cnt = 0;
    bool spatial_mode = false;
    uint64_t access_count = 0;
    uint32_t miss_count = 0;
};

std::vector<SetState> sets(LLC_SETS);

// PC-based reuse predictor
std::unordered_map<uint64_t, int8_t> pc_reuse_table;

// Stats
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

// Initialize replacement state
void InitReplacementState() {
    for (auto& set : sets) {
        set.lines.resize(LLC_WAYS);
        set.strides.resize(STRIDE_WINDOW, 0);
        set.last_addr = 0;
        set.stride_ptr = 0;
        set.spatial_cnt = 0;
        set.spatial_mode = false;
        set.access_count = 0;
        set.miss_count = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            set.lines[way].tag = 0;
            set.lines[way].last_PC = 0;
            set.lines[way].last_access = 0;
            set.lines[way].lru_stack = way;
        }
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

    // --- Spatial locality detection ---
    int64_t stride = (s.last_addr == 0) ? 0 : (int64_t(paddr >> 6) - int64_t(s.last_addr));
    s.strides[s.stride_ptr] = stride;
    s.stride_ptr = (s.stride_ptr + 1) % STRIDE_WINDOW;
    s.last_addr = paddr >> 6;

    // Count most common stride in window
    std::unordered_map<int64_t, int> stride_hist;
    for (int i = 0; i < STRIDE_WINDOW; i++) {
        stride_hist[s.strides[i]]++;
    }
    int max_stride_cnt = 0;
    for (const auto& kv : stride_hist) {
        if (kv.first == 0) continue; // skip zero stride
        max_stride_cnt = std::max(max_stride_cnt, kv.second);
    }
    s.spatial_mode = (max_stride_cnt >= SPATIAL_THRESHOLD);

    // --- Victim selection ---
    // If spatial mode, evict LRU among lines with lowest spatial reuse (oldest access)
    if (s.spatial_mode) {
        uint32_t victim = 0;
        uint64_t oldest_access = s.lines[0].last_access;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.lines[way].last_access <= oldest_access) {
                oldest_access = s.lines[way].last_access;
                victim = way;
            }
        }
        return victim;
    }

    // Otherwise, use PC-based reuse prediction, break ties with LRU
    int8_t min_reuse = PC_REUSE_MAX + 1;
    uint32_t victim = 0;
    uint8_t max_lru = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        LineState& line = s.lines[way];
        int8_t reuse_score = pc_reuse_table.count(line.last_PC) ? pc_reuse_table[line.last_PC] : 0;
        if (reuse_score < min_reuse ||
           (reuse_score == min_reuse && line.lru_stack >= max_lru)) {
            min_reuse = reuse_score;
            max_lru = line.lru_stack;
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
    if (!hit) total_evictions++;

    // Update line metadata
    line.tag = paddr >> 6;
    line.last_PC = PC;
    line.last_access = s.access_count;

    // Update PC-based reuse table
    auto& reuse = pc_reuse_table[PC];
    if (hit) {
        if (reuse < PC_REUSE_MAX) reuse++;
    } else {
        if (reuse > PC_REUSE_MIN) reuse--;
    }

    // Update LRU stack: move this way to MRU (0), increment others if needed
    uint8_t old_lru = line.lru_stack;
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (sets[set].lines[w].lru_stack < old_lru)
            continue;
        if (w == way)
            sets[set].lines[w].lru_stack = 0;
        else if (sets[set].lines[w].lru_stack < LLC_WAYS - 1)
            sets[set].lines[w].lru_stack++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ARSL: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}