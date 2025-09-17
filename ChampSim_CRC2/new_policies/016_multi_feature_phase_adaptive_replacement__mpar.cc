#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <random>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Policy parameters ---
#define REGION_SIZE 512
#define PHASE_WINDOW 2048
#define SPATIAL_RATIO_THRESHOLD 0.6
#define FREQ_RATIO_THRESHOLD 0.3
#define REUSE_MAX 3
#define FREQ_MAX 7

enum PhaseType { PHASE_UNKNOWN = 0, PHASE_SPATIAL = 1, PHASE_TEMPORAL = 2, PHASE_IRREGULAR = 3 };

struct BlockMeta {
    uint64_t tag;
    uint8_t reuse;      // Recency/Reuse counter (RRIP style)
    uint8_t freq;       // Frequency estimator
    uint64_t region;    // Region ID for spatial proximity
    bool valid;
};

struct SetMeta {
    std::vector<BlockMeta> blocks;
    uint64_t last_addr;
    uint32_t spatial_hits;
    uint32_t total_hits;
    uint32_t freq_hits;
    uint32_t access_count;
    PhaseType phase;
    // For random eviction in irregular phase
    std::mt19937 rng;
};

std::vector<SetMeta> sets(LLC_SETS);

// --- Helper: region id ---
inline uint64_t region_id(uint64_t paddr) {
    return paddr / REGION_SIZE;
}

// --- Initialize replacement state ---
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
        sets[s].last_addr = 0;
        sets[s].spatial_hits = 0;
        sets[s].total_hits = 0;
        sets[s].freq_hits = 0;
        sets[s].access_count = 0;
        sets[s].phase = PHASE_UNKNOWN;
        sets[s].rng.seed(s * 12345 + 6789); // unique seed per set
    }
}

// --- Periodically classify set phase ---
void update_phase(SetMeta& sm) {
    if (sm.access_count % PHASE_WINDOW == 0 && sm.access_count > 0) {
        float spatial_ratio = (float)sm.spatial_hits / (float)PHASE_WINDOW;
        float freq_ratio = (float)sm.freq_hits / (float)PHASE_WINDOW;
        // Prioritize spatial, then temporal, then irregular
        if (spatial_ratio > SPATIAL_RATIO_THRESHOLD)
            sm.phase = PHASE_SPATIAL;
        else if (freq_ratio > FREQ_RATIO_THRESHOLD)
            sm.phase = PHASE_TEMPORAL;
        else
            sm.phase = PHASE_IRREGULAR;
        // Reset counters for next interval
        sm.spatial_hits = 0;
        sm.total_hits = 0;
        sm.freq_hits = 0;
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

    uint32_t victim = 0;
    uint64_t curr_region = region_id(paddr);

    if (sm.phase == PHASE_SPATIAL) {
        // Evict blocks outside region, then by lowest reuse, then by lowest freq
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
    } else if (sm.phase == PHASE_TEMPORAL) {
        // Evict block with lowest freq, then highest reuse
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
        // IRREGULAR: RRIP + randomization (evict highest reuse, break ties randomly)
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

    uint64_t curr_region = region_id(paddr);

    // Detect spatial hit
    bool spatial = (bm.valid && bm.region == curr_region);
    if (spatial) sm.spatial_hits++;

    // Frequency hit: if block seen multiple times recently
    if (hit && bm.freq < FREQ_MAX) bm.freq++;
    if (hit && bm.freq > 0) sm.freq_hits++;

    if (hit) {
        bm.reuse = 0; // MRU on hit
    } else {
        // Insert policy depends on phase
        if (sm.phase == PHASE_SPATIAL) {
            bm.reuse = 1;
            bm.freq = 1;
        } else if (sm.phase == PHASE_TEMPORAL) {
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

    sm.last_addr = paddr;
    sm.total_hits += hit;
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " phase: " << sets[s].phase << " | ";
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            std::cout << "[R:" << (int)sets[s].blocks[w].reuse
                << ",F:" << (int)sets[s].blocks[w].freq
                << ",G:" << (int)sets[s].blocks[w].region
                << ",V:" << sets[s].blocks[w].valid << "] ";
        }
        std::cout << "\n";
    }
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    // No-op
}