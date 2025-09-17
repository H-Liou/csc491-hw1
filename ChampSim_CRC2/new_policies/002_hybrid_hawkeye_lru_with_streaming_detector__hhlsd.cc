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
constexpr int STREAM_WINDOW = 128;
constexpr float STREAM_THRESHOLD = 0.80f; // If miss rate > threshold, treat as streaming

// Replacement state per line
struct LineState {
    uint64_t tag = 0;
    uint64_t last_PC = 0;
    uint64_t last_access = 0;
    uint8_t lru_stack = 0; // 0 = MRU, LLC_WAYS-1 = LRU
};

// Per-set state
struct SetState {
    std::vector<LineState> lines;
    uint64_t access_count = 0;
    uint32_t miss_count = 0;
};

std::vector<SetState> sets(LLC_SETS);

// Simple PC-based reuse predictor: PC -> reuse score
std::unordered_map<uint64_t, int8_t> pc_reuse_table;

// Stats
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

// Initialize replacement state
void InitReplacementState() {
    for (auto& set : sets) {
        set.lines.resize(LLC_WAYS);
        set.access_count = 0;
        set.miss_count = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            set.lines[way].tag = 0;
            set.lines[way].last_PC = 0;
            set.lines[way].last_access = 0;
            set.lines[way].lru_stack = way; // initialize LRU stack
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

    // Streaming detection: calculate miss rate over window
    float miss_rate = (s.access_count > STREAM_WINDOW) ?
        float(s.miss_count) / float(s.access_count) : 0.0f;
    bool streaming = (miss_rate > STREAM_THRESHOLD);

    // If streaming, evict LRU
    if (streaming) {
        // Find line with max lru_stack (LRU)
        uint32_t victim = 0;
        uint8_t max_lru = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.lines[way].lru_stack >= max_lru) {
                max_lru = s.lines[way].lru_stack;
                victim = way;
            }
        }
        return victim;
    }

    // Otherwise, select line with lowest reuse prediction, break ties with LRU
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
    std::cout << "HHLSD: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}