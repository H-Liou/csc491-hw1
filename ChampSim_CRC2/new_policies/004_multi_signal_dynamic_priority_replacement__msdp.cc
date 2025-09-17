#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int STRIDE_WINDOW = 32;
constexpr int SPATIAL_THRESHOLD = 24; // >=24/32 same stride = spatial
constexpr int SCORE_FREQ_WEIGHT = 2;
constexpr int SCORE_RECENCY_WEIGHT = 2;
constexpr int SCORE_SPATIAL_WEIGHT = 2;

struct LineState {
    uint64_t tag = 0;
    uint64_t last_access = 0; // timestamp
    uint32_t access_count = 0; // frequency
    bool spatial_reuse = false;
    uint8_t lru_stack = 0;
};

struct SetState {
    std::vector<LineState> lines;
    std::vector<int64_t> strides; // recent access strides
    uint64_t last_addr = 0;
    uint32_t stride_ptr = 0;
    bool spatial_mode = false;
    uint64_t access_count = 0;
    uint32_t miss_count = 0;
    // Dynamic weights for scoring
    int freq_weight = SCORE_FREQ_WEIGHT;
    int recency_weight = SCORE_RECENCY_WEIGHT;
    int spatial_weight = SCORE_SPATIAL_WEIGHT;
};

std::vector<SetState> sets(LLC_SETS);

// Stats
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

void InitReplacementState() {
    for (auto& set : sets) {
        set.lines.resize(LLC_WAYS);
        set.strides.resize(STRIDE_WINDOW, 0);
        set.last_addr = 0;
        set.stride_ptr = 0;
        set.spatial_mode = false;
        set.access_count = 0;
        set.miss_count = 0;
        set.freq_weight = SCORE_FREQ_WEIGHT;
        set.recency_weight = SCORE_RECENCY_WEIGHT;
        set.spatial_weight = SCORE_SPATIAL_WEIGHT;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            set.lines[way].tag = 0;
            set.lines[way].last_access = 0;
            set.lines[way].access_count = 0;
            set.lines[way].spatial_reuse = false;
            set.lines[way].lru_stack = way;
        }
    }
    total_hits = total_misses = total_evictions = 0;
}

// Helper: update spatial mode and stride history
void UpdateSpatialMode(SetState& s, uint64_t paddr) {
    int64_t stride = (s.last_addr == 0) ? 0 : (int64_t(paddr >> 6) - int64_t(s.last_addr));
    s.strides[s.stride_ptr] = stride;
    s.stride_ptr = (s.stride_ptr + 1) % STRIDE_WINDOW;
    s.last_addr = paddr >> 6;

    std::unordered_map<int64_t, int> stride_hist;
    for (int i = 0; i < STRIDE_WINDOW; i++) {
        stride_hist[s.strides[i]]++;
    }
    int max_stride_cnt = 0;
    for (const auto& kv : stride_hist) {
        if (kv.first == 0) continue;
        max_stride_cnt = std::max(max_stride_cnt, kv.second);
    }
    s.spatial_mode = (max_stride_cnt >= SPATIAL_THRESHOLD);
}

// Helper: dynamically adjust weights based on miss/hit ratio and spatial mode
void AdjustWeights(SetState& s) {
    // Every 512 accesses, tune weights
    if (s.access_count % 512 == 0 && s.access_count > 0) {
        double miss_rate = double(s.miss_count) / s.access_count;
        if (s.spatial_mode) {
            // Streaming phase: boost spatial, reduce recency/freq
            s.spatial_weight = 3;
            s.recency_weight = 1;
            s.freq_weight = 1;
        } else if (miss_rate > 0.30) {
            // Irregular/poor locality: boost recency/freq, reduce spatial
            s.spatial_weight = 1;
            s.recency_weight = 3;
            s.freq_weight = 3;
        } else {
            // Balanced phase
            s.spatial_weight = 2;
            s.recency_weight = 2;
            s.freq_weight = 2;
        }
        // Reset counters for next window
        s.access_count = 0;
        s.miss_count = 0;
    }
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

    UpdateSpatialMode(s, paddr);
    AdjustWeights(s);

    // Build score for each way
    uint64_t min_score = UINT64_MAX;
    uint32_t victim = 0;
    uint64_t now = s.access_count;

    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        LineState& line = s.lines[way];
        // Recency: older is worse, so use (now - last_access)
        uint64_t recency_score = now - line.last_access;
        // Frequency: less accessed is worse, so use inverse
        uint64_t freq_score = (line.access_count == 0) ? UINT64_MAX : (10000 / line.access_count);
        // Spatial: penalize lines with no spatial reuse in streaming mode
        uint64_t spatial_score = (s.spatial_mode && !line.spatial_reuse) ? 1000 : 0;

        uint64_t score =
            s.recency_weight * recency_score +
            s.freq_weight * freq_score +
            s.spatial_weight * spatial_score;

        // Tie-break with LRU stack
        if (score < min_score ||
            (score == min_score && line.lru_stack > s.lines[victim].lru_stack)) {
            min_score = score;
            victim = way;
        }
    }
    return victim;
}

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

    // Update metadata
    line.tag = paddr >> 6;
    line.last_access = s.access_count;
    line.access_count = hit ? line.access_count + 1 : 1;

    // Spatial reuse: if spatial mode and stride matches most common, set flag
    if (s.spatial_mode) {
        int64_t stride = (s.last_addr == 0) ? 0 : (int64_t(paddr >> 6) - int64_t(s.last_addr));
        // Find most common stride
        std::unordered_map<int64_t, int> stride_hist;
        for (int i = 0; i < STRIDE_WINDOW; i++) {
            stride_hist[s.strides[i]]++;
        }
        int64_t best_stride = 0;
        int max_cnt = 0;
        for (const auto& kv : stride_hist) {
            if (kv.first == 0) continue;
            if (kv.second > max_cnt) {
                max_cnt = kv.second;
                best_stride = kv.first;
            }
        }
        line.spatial_reuse = (stride == best_stride && stride != 0);
    } else {
        line.spatial_reuse = false;
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

void PrintStats() {
    std::cout << "MSDP: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}