#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int RRIP_BITS = 2;
constexpr int RRIP_MAX = (1 << RRIP_BITS) - 1; // 3
constexpr int RRIP_LONG = RRIP_MAX; // Insert with 3 for streaming
constexpr int RRIP_SHORT = 0;       // Insert with 0 for temporal
constexpr int RRIP_MID = 1;         // Insert with 1 for spatial

// Per-set predictor
struct SetState {
    std::vector<uint8_t> rrip;
    std::vector<uint64_t> tags;
    std::vector<bool> valid;
    // For stride detection
    uint64_t last_addr = 0;
    std::vector<uint32_t> recent_strides;
    // For hit/miss tracking
    uint32_t recent_hits = 0;
    uint32_t recent_misses = 0;
    uint8_t reuse_bias = 1; // 0: streaming, 1: spatial, 2: temporal
    uint8_t reuse_counter = 4; // saturating counter [0,7]
};

std::vector<SetState> sets(LLC_SETS);

// Global bimodal insertion selector
uint32_t global_miss_count = 0, global_access_count = 0;
uint8_t global_insert_bias = 1; // 0: evict fast, 1: retain, flips on miss spike

// --- Initialization ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.rrip.assign(LLC_WAYS, RRIP_MAX);
        set.tags.assign(LLC_WAYS, 0);
        set.valid.assign(LLC_WAYS, false);
        set.last_addr = 0;
        set.recent_strides.clear();
        set.recent_hits = 0;
        set.recent_misses = 0;
        set.reuse_bias = 1;
        set.reuse_counter = 4;
    }
    global_miss_count = 0;
    global_access_count = 0;
    global_insert_bias = 1;
}

// --- Victim Selection (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState& s = sets[set];
    // Prefer invalid
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!s.valid[way])
            return way;
    }
    // SRRIP: Find RRIP_MAX
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.rrip[way] == RRIP_MAX)
                return way;
        }
        // Age all lines
        for (auto& r : s.rrip)
            if (r < RRIP_MAX) r++;
    }
}

// --- Per-set Temporal/Spatial/Streaming Predictor ---
void UpdateSetPredictor(SetState& s, uint64_t curr_addr, bool hit) {
    // Stride detection
    if (s.last_addr != 0) {
        uint32_t stride = static_cast<uint32_t>(curr_addr - s.last_addr);
        if (stride != 0) {
            s.recent_strides.push_back(stride);
            if (s.recent_strides.size() > 8)
                s.recent_strides.erase(s.recent_strides.begin());
        }
    }
    s.last_addr = curr_addr;

    // Hit/miss window
    if (hit) s.recent_hits++;
    else s.recent_misses++;
    if (s.recent_hits + s.recent_misses >= 32) {
        // Streaming: high miss, irregular stride
        uint32_t max_stride = 0, stride_count = 0;
        for (auto val : s.recent_strides) {
            uint32_t cnt = std::count(s.recent_strides.begin(), s.recent_strides.end(), val);
            if (cnt > stride_count) {
                stride_count = cnt;
                max_stride = val;
            }
        }
        bool spatial = (stride_count >= 6); // regular stride
        bool streaming = (s.recent_misses > 24 && !spatial);
        bool temporal = (s.recent_hits > 16 && !spatial);

        if (streaming) {
            if (s.reuse_counter > 0) s.reuse_counter--;
        } else if (spatial) {
            if (s.reuse_counter < 7) s.reuse_counter++;
        } else if (temporal) {
            if (s.reuse_counter < 7) s.reuse_counter++;
        }
        // Bias: 0=streaming, 1=spatial, 2=temporal
        if (s.reuse_counter <= 2) s.reuse_bias = 0;
        else if (spatial) s.reuse_bias = 1;
        else s.reuse_bias = 2;

        s.recent_hits = 0;
        s.recent_misses = 0;
        s.recent_strides.clear();
    }
}

// --- Global Bimodal Insertion Selector ---
void UpdateGlobalBias(bool miss) {
    global_access_count++;
    if (miss) global_miss_count++;
    if (global_access_count >= 4096) {
        // If miss rate > 60%, flip to "evict fast" for next period
        if (global_miss_count * 100 / global_access_count > 60)
            global_insert_bias = 0;
        else
            global_insert_bias = 1;
        global_access_count = 0;
        global_miss_count = 0;
    }
}

// --- Replacement State Update ---
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
    uint64_t line_addr = paddr >> 6;

    // Update predictors
    UpdateSetPredictor(s, line_addr, hit);
    UpdateGlobalBias(!hit);

    // On hit: promote
    if (hit) {
        s.rrip[way] = RRIP_SHORT;
        s.tags[way] = line_addr;
        s.valid[way] = true;
        return;
    }

    // On miss: insertion policy
    uint8_t ins_rrip = RRIP_SHORT;
    if (global_insert_bias == 0) {
        // Global streaming/evict mode
        ins_rrip = RRIP_LONG;
    } else {
        // Per-set bias
        if (s.reuse_bias == 0)      ins_rrip = RRIP_LONG; // streaming
        else if (s.reuse_bias == 1) ins_rrip = RRIP_MID;  // spatial
        else                        ins_rrip = RRIP_SHORT; // temporal
    }
    s.rrip[way] = ins_rrip;
    s.tags[way] = line_addr;
    s.valid[way] = true;
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "HSB-TSP: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}