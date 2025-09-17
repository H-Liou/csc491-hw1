#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <random>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

#define REGION_SIZE 512
#define PHASE_WINDOW 1024
#define SPATIAL_HIT_THRESHOLD 0.5
#define FREQ_HIT_THRESHOLD 0.2
#define REUSE_MAX 3
#define FREQ_MAX 7

enum LocalityType { LOC_UNKNOWN = 0, LOC_SPATIAL = 1, LOC_TEMPORAL = 2, LOC_NONE = 3 };

struct BlockMeta {
    uint64_t tag;
    uint8_t reuse;    // RRIP-style recency counter
    uint8_t freq;     // Frequency estimator
    uint64_t region;  // Region ID for spatial locality
    bool valid;
};

struct SetMeta {
    std::vector<BlockMeta> blocks;
    uint32_t spatial_hits;
    uint32_t freq_hits;
    uint32_t access_count;
    LocalityType locality;
    std::mt19937 rng;
};

std::vector<SetMeta> sets(LLC_SETS);

// Helper: region id
inline uint64_t region_id(uint64_t paddr) {
    return paddr / REGION_SIZE;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].tag = 0;
            sets[s].blocks[w].reuse = REUSE_MAX;
            sets[s].blocks[w].freq = 0;
            sets[s].blocks[w].region = 0;
            sets[s].blocks[w].valid = false;
        }
        sets[s].spatial_hits = 0;
        sets[s].freq_hits = 0;
        sets[s].access_count = 0;
        sets[s].locality = LOC_UNKNOWN;
        sets[s].rng.seed(s * 9876 + 54321);
    }
}

// Periodically classify set locality
void update_locality(SetMeta& sm) {
    if (sm.access_count % PHASE_WINDOW == 0 && sm.access_count > 0) {
        float spatial_ratio = (float)sm.spatial_hits / (float)PHASE_WINDOW;
        float freq_ratio = (float)sm.freq_hits / (float)PHASE_WINDOW;
        if (spatial_ratio > SPATIAL_HIT_THRESHOLD)
            sm.locality = LOC_SPATIAL;
        else if (freq_ratio > FREQ_HIT_THRESHOLD)
            sm.locality = LOC_TEMPORAL;
        else
            sm.locality = LOC_NONE;
        sm.spatial_hits = 0;
        sm.freq_hits = 0;
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
    SetMeta &sm = sets[set];
    update_locality(sm);

    uint32_t victim = 0;
    uint64_t curr_region = region_id(paddr);

    if (sm.locality == LOC_SPATIAL) {
        // Prefer to evict blocks outside current region, then lowest reuse, then lowest freq
        int best_score = -10000;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            int score = 0;
            if (!sm.blocks[w].valid) score += 100;
            if (sm.blocks[w].region != curr_region) score += 10;
            score -= sm.blocks[w].reuse * 2;
            score -= sm.blocks[w].freq;
            if (score > best_score) {
                best_score = score;
                victim = w;
            }
        }
    } else if (sm.locality == LOC_TEMPORAL) {
        // Prefer to evict block with lowest freq, then highest reuse
        int best_score = -10000;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            int score = 0;
            if (!sm.blocks[w].valid) score += 100;
            score -= sm.blocks[w].freq * 3;
            score -= sm.blocks[w].reuse;
            if (score > best_score) {
                best_score = score;
                victim = w;
            }
        }
    } else {
        // LOC_NONE: RRIP + randomization (evict highest reuse, break ties randomly)
        uint8_t max_reuse = 0;
        std::vector<uint32_t> candidates;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (!sm.blocks[w].valid) {
                victim = w;
                break;
            }
            if (sm.blocks[w].reuse > max_reuse) {
                max_reuse = sm.blocks[w].reuse;
                candidates.clear();
                candidates.push_back(w);
            } else if (sm.blocks[w].reuse == max_reuse) {
                candidates.push_back(w);
            }
        }
        if (candidates.size() > 1) {
            std::uniform_int_distribution<uint32_t> dist(0, candidates.size() - 1);
            victim = candidates[dist(sm.rng)];
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
    SetMeta &sm = sets[set];
    BlockMeta &bm = sm.blocks[way];
    sm.access_count++;

    uint64_t curr_region = region_id(paddr);

    // Detect spatial hit
    if (bm.valid && bm.region == curr_region) sm.spatial_hits++;

    // Frequency hit: accessed multiple times
    if (hit && bm.freq < FREQ_MAX) bm.freq++;
    if (hit && bm.freq > 0) sm.freq_hits++;

    if (hit) {
        bm.reuse = 0; // MRU on hit
    } else {
        // Insert policy depends on locality
        if (sm.locality == LOC_SPATIAL) {
            bm.reuse = 1;
            bm.freq = 1;
        } else if (sm.locality == LOC_TEMPORAL) {
            bm.reuse = 2;
            bm.freq = 2;
        } else {
            bm.reuse = REUSE_MAX;
            bm.freq = 0;
        }
    }

    bm.tag = paddr;
    bm.region = curr_region;
    bm.valid = true;
}

// Print end-of-simulation statistics
void PrintStats() {
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " locality: " << sets[s].locality << " | ";
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            std::cout << "[R:" << (int)sets[s].blocks[w].reuse
                << ",F:" << (int)sets[s].blocks[w].freq
                << ",G:" << (int)sets[s].blocks[w].region
                << ",V:" << sets[s].blocks[w].valid << "] ";
        }
        std::cout << "\n";
    }
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}