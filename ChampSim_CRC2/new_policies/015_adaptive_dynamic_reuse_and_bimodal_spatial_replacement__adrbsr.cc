#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <cmath>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Policy parameters ---
#define DRC_MAX 3         // Dynamic Reuse Counter max (RRIP style)
#define SPATIAL_REGION 512 // Region size for spatial proximity
#define STRIDE_WINDOW 8   // Number of strides to track per set
#define SPATIAL_THRESHOLD 5 // # of spatial hits to classify as spatial
#define PHASE_INTERVAL 4096 // How often to reclassify set phase

enum SetPhase { PHASE_UNKNOWN = 0, PHASE_SPATIAL = 1, PHASE_IRREGULAR = 2 };

struct BlockMeta {
    uint64_t tag;
    uint8_t drc;         // Dynamic Reuse Counter (temporal locality)
    uint64_t region;     // Region ID for spatial proximity
    bool spatial_hit;    // Last access was spatially correlated
};

struct SetMeta {
    std::vector<BlockMeta> blocks;
    std::vector<uint64_t> stride_hist;
    uint64_t last_addr;
    uint32_t spatial_hits;
    uint32_t irregular_hits;
    SetPhase phase;
    uint64_t access_count;
};

std::vector<SetMeta> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].tag = 0;
            sets[s].blocks[w].drc = DRC_MAX; // Inserted as "long re-use"
            sets[s].blocks[w].region = 0;
            sets[s].blocks[w].spatial_hit = false;
        }
        sets[s].stride_hist.clear();
        sets[s].last_addr = 0;
        sets[s].spatial_hits = 0;
        sets[s].irregular_hits = 0;
        sets[s].phase = PHASE_UNKNOWN;
        sets[s].access_count = 0;
    }
}

// --- Helper: detect spatial correlation ---
bool is_spatial(uint64_t paddr, SetMeta& sm) {
    if (sm.last_addr == 0) return false;
    uint64_t stride = std::abs((int64_t)paddr - (int64_t)sm.last_addr);
    if (stride == 0) return false;
    // Track stride history
    sm.stride_hist.push_back(stride);
    if (sm.stride_hist.size() > STRIDE_WINDOW)
        sm.stride_hist.erase(sm.stride_hist.begin());
    // If most recent strides are similar, treat as spatial
    int spatial_count = 0;
    for (auto s : sm.stride_hist) {
        if (s <= SPATIAL_REGION)
            spatial_count++;
    }
    return spatial_count >= (STRIDE_WINDOW / 2);
}

// --- Helper: region id ---
inline uint64_t region_id(uint64_t paddr) {
    return paddr / SPATIAL_REGION;
}

// --- Periodically classify set phase ---
void update_phase(SetMeta& sm) {
    if (sm.access_count % PHASE_INTERVAL == 0) {
        if (sm.spatial_hits >= SPATIAL_THRESHOLD)
            sm.phase = PHASE_SPATIAL;
        else
            sm.phase = PHASE_IRREGULAR;
        // Reset counters for next interval
        sm.spatial_hits = 0;
        sm.irregular_hits = 0;
    }
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
    SetMeta &sm = sets[set];
    update_phase(sm);

    // PHASE_SPATIAL: prefer to evict blocks outside region, or with high DRC
    // PHASE_IRREGULAR: RRIP-like, evict block with highest DRC
    uint32_t victim = 0;
    if (sm.phase == PHASE_SPATIAL) {
        uint64_t curr_region = region_id(paddr);
        int max_score = -10000;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            int score = 0;
            // Prefer to evict blocks outside spatial region
            if (sm.blocks[w].region != curr_region)
                score += 5;
            // Penalize blocks with high DRC (less reuse)
            score += sm.blocks[w].drc * 2;
            // Prefer to evict blocks not spatially correlated
            if (!sm.blocks[w].spatial_hit)
                score += 2;
            // Favor empty blocks
            if (sm.blocks[w].tag == 0)
                score += 10;
            if (score > max_score) {
                max_score = score;
                victim = w;
            }
        }
    } else {
        // IRREGULAR: RRIP style
        uint8_t max_drc = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (sm.blocks[w].drc > max_drc || sm.blocks[w].tag == 0) {
                max_drc = sm.blocks[w].drc;
                victim = w;
            }
        }
    }
    return victim;
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
    SetMeta &sm = sets[set];
    BlockMeta &bm = sm.blocks[way];
    sm.access_count++;

    // Update stride history and spatial detection
    bool spatial = is_spatial(paddr, sm);
    bm.spatial_hit = spatial;
    bm.region = region_id(paddr);

    // Update phase counters
    if (spatial) sm.spatial_hits++;
    else sm.irregular_hits++;

    // Update DRC (reuse counter)
    if (hit) {
        bm.drc = 0; // MRU on hit
    } else {
        if (sm.phase == PHASE_SPATIAL) {
            // Insert as likely-to-be-reused if spatial
            bm.drc = spatial ? 1 : DRC_MAX;
        } else {
            // Insert as long-reuse (RRIP style)
            bm.drc = DRC_MAX;
        }
    }

    // Update tag
    bm.tag = paddr;

    // Update last_addr for stride
    sm.last_addr = paddr;
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    // Print phase and DRC for first 4 sets
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " phase: " << sets[s].phase << " | ";
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            std::cout << "[D:" << (int)sets[s].blocks[w].drc
                      << ",R:" << (int)sets[s].blocks[w].region
                      << ",S:" << sets[s].blocks[w].spatial_hit << "] ";
        }
        std::cout << "\n";
    }
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    // No-op
}