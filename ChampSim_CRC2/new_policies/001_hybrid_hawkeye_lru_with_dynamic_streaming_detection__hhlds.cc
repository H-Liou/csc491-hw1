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
constexpr uint32_t HAWKEYE_MAX = 7;              // Max value for PC reuse predictor
constexpr uint32_t STREAM_WINDOW = 128;          // Window for streaming detection
constexpr float STREAM_THRESHOLD = 0.82f;        // Miss rate threshold for streaming

// Replacement state per line
struct LineState {
    uint64_t tag = 0;
    uint64_t last_PC = 0;
    uint8_t hawkeye_score = 0; // 0 = not reused, max = reused
    uint8_t lru_position = 0;  // 0 = MRU, LLC_WAYS-1 = LRU
    uint64_t last_access = 0;
};

// Per-set state
struct SetState {
    std::vector<LineState> lines;
    uint64_t access_count = 0;
    uint32_t miss_count = 0;
    std::vector<uint8_t> lru_stack; // LRU positions
};

// PC-based reuse predictor (Hawkeye-style)
std::unordered_map<uint64_t, uint8_t> hawkeye_table; // PC -> reuse score

// Stats
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        SetState st;
        st.lines.resize(LLC_WAYS);
        st.access_count = 0;
        st.miss_count = 0;
        st.lru_stack.resize(LLC_WAYS);
        for (uint8_t i = 0; i < LLC_WAYS; ++i) st.lru_stack[i] = i;
        for (uint8_t i = 0; i < LLC_WAYS; ++i) {
            st.lines[i].lru_position = i;
            st.lines[i].hawkeye_score = HAWKEYE_MAX/2;
        }
        sets.push_back(st);
    }
    hawkeye_table.clear();
    total_hits = total_misses = total_evictions = 0;
}

// Global state
std::vector<SetState> sets;

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

    // Streaming phase detection
    float miss_rate = (s.access_count > STREAM_WINDOW) ?
        float(s.miss_count) / float(s.access_count) : 0.0f;
    bool streaming = (miss_rate > STREAM_THRESHOLD);

    // Find all lines predicted "not reused" (hawkeye_score low)
    std::vector<uint32_t> candidates;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        LineState& line = s.lines[way];
        uint8_t pred = hawkeye_table[line.last_PC];
        if (pred <= HAWKEYE_MAX/3) candidates.push_back(way);
    }

    uint32_t victim = 0;
    if (streaming || candidates.empty()) {
        // Streaming: evict true LRU
        uint8_t max_lru = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.lines[way].lru_position > max_lru) {
                max_lru = s.lines[way].lru_position;
                victim = way;
            }
        }
    } else {
        // Prefer predicted not-reused, pick oldest among them
        uint64_t oldest = 0;
        for (auto way : candidates) {
            if (s.lines[way].last_access <= oldest || oldest == 0) {
                oldest = s.lines[way].last_access;
                victim = way;
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
    SetState& s = sets[set];
    LineState& line = s.lines[way];

    if (hit) total_hits++; else { total_misses++; s.miss_count++; }

    // Update line metadata
    line.tag = paddr >> 6;
    line.last_PC = PC;
    line.last_access = s.access_count;

    // Update Hawkeye-style reuse predictor
    auto& reuse = hawkeye_table[PC];
    if (hit) {
        if (reuse < HAWKEYE_MAX) reuse++;
    } else {
        if (reuse > 0) reuse--;
    }
    line.hawkeye_score = reuse;

    // Update LRU stack positions
    uint8_t old_pos = line.lru_position;
    for (uint32_t i = 0; i < LLC_WAYS; ++i) {
        if (s.lines[i].lru_position < old_pos)
            s.lines[i].lru_position++;
    }
    line.lru_position = 0;

    // Track evictions
    if (!hit) total_evictions++;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "HHLDS: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}