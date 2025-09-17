#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block replacement state ---
struct BlockState {
    uint8_t freq;            // Frequency counter (LFU segment)
    uint8_t recency;         // LRU stack position (LRU segment)
    uint32_t spatial_group;  // Page-based spatial tag
    uint64_t last_access;    // For tie-breaking
    bool in_lfu;             // Segment membership
};

std::vector<std::vector<BlockState>> block_state(LLC_SETS, std::vector<BlockState>(LLC_WAYS));

// --- Per-set segment control ---
struct SetSegment {
    uint8_t lfu_size;        // Number of LFU slots (rest are LRU)
    uint16_t lfu_hits;       // Recent hits in LFU
    uint16_t lru_hits;       // Recent hits in LRU
    uint64_t last_segment_update;
};

std::vector<SetSegment> set_segment(LLC_SETS);

uint64_t global_access_counter = 0;
uint64_t total_evictions = 0;

// --- Utility: spatial group hash ---
inline uint32_t spatial_hash(uint64_t addr) {
    // Group by 4KB page
    return (uint32_t)((addr >> 12) & 0xFFFF);
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_state[set][way] = {0, (uint8_t)way, 0, 0, way < LLC_WAYS/2}; // LFU lower half
        }
        set_segment[set] = {LLC_WAYS/2, 0, 0, 0};
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
    SetSegment &seg = set_segment[set];

    // --- Dynamic segment adjustment every 2048 accesses ---
    if (global_access_counter - seg.last_segment_update > 2048) {
        if (seg.lfu_hits > seg.lru_hits && seg.lfu_size < LLC_WAYS - 2)
            seg.lfu_size++; // Grow LFU
        else if (seg.lru_hits > seg.lfu_hits && seg.lfu_size > 2)
            seg.lfu_size--; // Shrink LFU
        seg.lfu_hits = seg.lru_hits = 0;
        seg.last_segment_update = global_access_counter;
    }

    // --- Victim selection ---
    uint32_t curr_group = spatial_hash(paddr);
    int victim_way = -1;
    float min_score = 1e9;

    for (int way = 0; way < LLC_WAYS; ++way) {
        BlockState &bs = block_state[set][way];
        float score = 0.0f;

        if (way < seg.lfu_size) {
            // LFU segment: evict least frequently used, penalize non-spatial
            score = (float)(15 - bs.freq) + ((bs.spatial_group == curr_group) ? -1.0f : 1.0f);
        } else {
            // LRU segment: evict oldest, penalize non-spatial
            score = (float)bs.recency + ((bs.spatial_group == curr_group) ? -1.0f : 1.0f);
        }
        // Tie-breaker: prefer older blocks if scores equal
        score += 0.01f * (float)(global_access_counter - bs.last_access) / 4096.0f;

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
    BlockState &bs = block_state[set][way];
    SetSegment &seg = set_segment[set];
    uint32_t curr_group = spatial_hash(paddr);

    // --- Update segment membership if needed ---
    if (way < seg.lfu_size)
        bs.in_lfu = true;
    else
        bs.in_lfu = false;

    // --- Update block state ---
    bs.spatial_group = curr_group;
    bs.last_access = global_access_counter;

    if (bs.in_lfu) {
        // LFU segment: frequency counter
        if (hit)
            bs.freq = std::min(bs.freq + 1, (uint8_t)15);
        else
            bs.freq = bs.freq / 2;
        seg.lfu_hits += hit;
    } else {
        // LRU segment: recency stack
        uint8_t old_recency = bs.recency;
        for (int w = seg.lfu_size; w < LLC_WAYS; ++w) {
            if (block_state[set][w].recency < old_recency)
                block_state[set][w].recency++;
        }
        bs.recency = seg.lfu_size;
        seg.lru_hits += hit;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "SARDSA: total_evictions=" << total_evictions << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    PrintStats();
}