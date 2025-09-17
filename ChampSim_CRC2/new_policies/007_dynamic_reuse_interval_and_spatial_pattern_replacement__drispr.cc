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
    uint32_t reuse_interval;   // Accesses since last use
    uint32_t spatial_group;    // Spatial group tag (hash of block addr)
    uint8_t  reuse_confidence; // Confidence in reuse prediction (0-7)
    uint64_t last_access;      // Global access counter at last access
};

std::vector<std::vector<BlockState>> block_state(LLC_SETS, std::vector<BlockState>(LLC_WAYS));

// --- Per-set spatial pattern detector ---
struct SetSpatialPattern {
    uint32_t last_group;        // Last accessed spatial group
    uint32_t streak;            // How many consecutive accesses to same group
    uint8_t  spatial_mode;      // 1 if spatial pattern detected, else 0
    uint64_t last_pattern_update;
};

std::vector<SetSpatialPattern> set_pattern(LLC_SETS);

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
            block_state[set][way] = {0, 0, 0, 0};
        }
        set_pattern[set] = {0, 0, 0, 0};
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

    SetSpatialPattern& sp = set_pattern[set];
    uint32_t curr_group = spatial_hash(paddr);

    // Detect spatial pattern: if last N accesses are to same group, enable spatial mode
    if (sp.last_group == curr_group) {
        sp.streak++;
    } else {
        sp.streak = 1;
        sp.last_group = curr_group;
    }
    // Update spatial mode every 512 accesses
    if (global_access_counter - sp.last_pattern_update > 512) {
        sp.spatial_mode = (sp.streak > 8) ? 1 : 0;
        sp.last_pattern_update = global_access_counter;
    }

    // Victim selection:
    // 1. If spatial pattern detected, protect blocks in current group.
    // 2. Otherwise, evict block with longest predicted reuse interval and lowest confidence.

    int victim_way = -1;
    uint32_t max_interval = 0;
    uint8_t min_confidence = 8;
    uint64_t oldest_access = 0;
    bool found = false;

    // First, try to evict blocks not in current spatial group if spatial mode is on
    if (sp.spatial_mode) {
        for (int way = 0; way < LLC_WAYS; ++way) {
            BlockState& bs = block_state[set][way];
            if (bs.spatial_group != curr_group) {
                // Prefer lowest confidence, then oldest
                if (!found ||
                    bs.reuse_confidence < min_confidence ||
                    (bs.reuse_confidence == min_confidence && bs.last_access < oldest_access)) {
                    victim_way = way;
                    min_confidence = bs.reuse_confidence;
                    oldest_access = bs.last_access;
                    found = true;
                }
            }
        }
        if (found) {
            total_evictions++;
            return victim_way;
        }
        // If all blocks are in current group, fall back to reuse interval
    }

    // Otherwise, evict block with largest reuse interval and lowest confidence
    for (int way = 0; way < LLC_WAYS; ++way) {
        BlockState& bs = block_state[set][way];
        uint32_t interval = global_access_counter - bs.last_access;
        // Prefer blocks with high interval, then low confidence, then oldest
        if (!found ||
            interval > max_interval ||
            (interval == max_interval && bs.reuse_confidence < min_confidence) ||
            (interval == max_interval && bs.reuse_confidence == min_confidence && bs.last_access < oldest_access)) {
            victim_way = way;
            max_interval = interval;
            min_confidence = bs.reuse_confidence;
            oldest_access = bs.last_access;
            found = true;
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
    uint32_t curr_group = spatial_hash(paddr);

    // Update reuse interval
    uint32_t interval = global_access_counter - bs.last_access;
    bs.reuse_interval = interval;

    // Update spatial group
    bs.spatial_group = curr_group;

    // Update reuse confidence: increment on hit, decay on miss
    if (hit)
        bs.reuse_confidence = std::min(bs.reuse_confidence + 1, (uint8_t)7);
    else
        bs.reuse_confidence = (bs.reuse_confidence > 0) ? bs.reuse_confidence - 1 : 0;

    // Update last access time
    bs.last_access = global_access_counter;
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "DRISPR: total_evictions=" << total_evictions << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    PrintStats();
}