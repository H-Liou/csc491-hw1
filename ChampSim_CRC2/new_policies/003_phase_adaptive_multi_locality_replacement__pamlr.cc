#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Replacement state per block ---
struct BlockState {
    uint32_t recency;         // LRU stack position (lower is newer)
    uint32_t freq;            // Frequency counter (decays slowly)
    uint32_t spatial_group;   // Spatial group tag (hash of block addr)
    uint64_t last_access;     // For tie-breaking
};

std::vector<std::vector<BlockState>> block_state(LLC_SETS, std::vector<BlockState>(LLC_WAYS));

// --- Per-set phase detection and scoring weights ---
struct SetPhase {
    uint32_t recent_hits;         // Hits in last window
    uint32_t recent_misses;       // Misses in last window
    uint32_t spatial_hits;        // Hits to same spatial group
    uint32_t freq_hits;           // Hits to high-frequency blocks
    uint32_t lru_hits;            // Hits to recently used blocks
    uint8_t  phase_mode;          // 0: regular, 1: irregular
    float    recency_weight;
    float    freq_weight;
    float    spatial_weight;
    uint64_t last_phase_update;
};

std::vector<SetPhase> set_phase(LLC_SETS);

// --- Global stats ---
uint64_t global_access_counter = 0;
uint64_t total_evictions = 0;

// --- Utility: spatial group hash ---
inline uint32_t spatial_hash(uint64_t addr) {
    // Simple page-based grouping (e.g., 4KB)
    return (uint32_t)((addr >> 12) & 0xFFFF);
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_state[set][way] = {way, 0, 0, 0};
        }
        set_phase[set] = {0, 0, 0, 0, 0, 0, 0.5f, 0.3f, 0.2f, 0};
    }
    global_access_counter = 0;
    total_evictions = 0;
}

// --- Find victim in the set ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    global_access_counter++;

    // Update phase weights every 4096 accesses per set
    SetPhase& sp = set_phase[set];
    if (global_access_counter - sp.last_phase_update > 4096) {
        // If spatial hits dominate, favor spatial locality
        if (sp.spatial_hits > sp.freq_hits && sp.spatial_hits > sp.lru_hits) {
            sp.recency_weight = 0.2f;
            sp.freq_weight = 0.3f;
            sp.spatial_weight = 0.5f;
            sp.phase_mode = 0; // Regular
        }
        // If frequency hits dominate, favor frequency
        else if (sp.freq_hits > sp.spatial_hits && sp.freq_hits > sp.lru_hits) {
            sp.recency_weight = 0.2f;
            sp.freq_weight = 0.6f;
            sp.spatial_weight = 0.2f;
            sp.phase_mode = 0; // Regular
        }
        // If LRU hits dominate, favor recency (irregular phase)
        else {
            sp.recency_weight = 0.7f;
            sp.freq_weight = 0.2f;
            sp.spatial_weight = 0.1f;
            sp.phase_mode = 1; // Irregular
        }
        // Reset stats for next window
        sp.spatial_hits = sp.freq_hits = sp.lru_hits = 0;
        sp.last_phase_update = global_access_counter;
    }

    // Compute scores for all blocks
    float min_score = 1e9;
    int victim_way = 0;
    uint32_t curr_group = spatial_hash(paddr);

    for (int way = 0; way < LLC_WAYS; ++way) {
        BlockState& bs = block_state[set][way];

        // Recency: lower is better (evict oldest)
        float recency_score = (float)bs.recency / LLC_WAYS;

        // Frequency: lower is better (evict least frequent)
        float freq_score = 1.0f - ((float)bs.freq / 15.0f);

        // Spatial: penalize blocks not in current group
        float spatial_score = (bs.spatial_group == curr_group) ? 0.0f : 1.0f;

        // Weighted sum
        float score = sp.recency_weight * recency_score +
                      sp.freq_weight * freq_score +
                      sp.spatial_weight * spatial_score +
                      0.01f * (float)(global_access_counter - bs.last_access) / 4096.0f; // tie-breaker

        if (score < min_score) {
            min_score = score;
            victim_way = way;
        }
    }
    total_evictions++;
    return victim_way;
}

// --- Update replacement state ---
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
    global_access_counter++;
    BlockState& bs = block_state[set][way];
    SetPhase& sp = set_phase[set];

    // Update recency stack: move accessed block to MRU
    uint32_t old_recency = bs.recency;
    for (int w = 0; w < LLC_WAYS; ++w) {
        if (block_state[set][w].recency < old_recency)
            block_state[set][w].recency++;
    }
    bs.recency = 0;

    // Update frequency counter
    if (hit)
        bs.freq = std::min(bs.freq + 1, 15u);
    else
        bs.freq = bs.freq / 2;

    // Update spatial group
    uint32_t curr_group = spatial_hash(paddr);
    bs.spatial_group = curr_group;

    // Update last access time
    bs.last_access = global_access_counter;

    // Update set-level stats for phase detection
    if (hit) {
        sp.recent_hits++;
        if (bs.spatial_group == curr_group)
            sp.spatial_hits++;
        if (bs.freq > 8)
            sp.freq_hits++;
        if (bs.recency < 4)
            sp.lru_hits++;
    } else {
        sp.recent_misses++;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "PAMLR: total_evictions=" << total_evictions << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    PrintStats();
}