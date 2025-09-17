#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include <random>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

#define REGION_SIZE 512
#define REUSE_WINDOW 128
#define SRRIP_MAX 3
#define REUSE_SCORE_MAX 7
#define REGION_SCORE_MAX 7

enum LocalityType { LOC_UNKNOWN = 0, LOC_REUSE = 1, LOC_SPATIAL = 2, LOC_RANDOM = 3 };

struct BlockMeta {
    uint64_t tag;
    uint8_t srrip;      // SRRIP-style recency counter
    uint8_t reuse_score;// Hawkeye-inspired reuse predictor
    uint64_t region;
    bool valid;
};

struct SetMeta {
    std::vector<BlockMeta> blocks;
    // Recently evicted addresses for reuse detection
    std::unordered_map<uint64_t, uint32_t> evicted_addr_time;
    uint32_t access_time;
    uint32_t reuse_hits;
    uint32_t region_hits;
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
            sets[s].blocks[w].srrip = SRRIP_MAX;
            sets[s].blocks[w].reuse_score = 0;
            sets[s].blocks[w].region = 0;
            sets[s].blocks[w].valid = false;
        }
        sets[s].evicted_addr_time.clear();
        sets[s].access_time = 0;
        sets[s].reuse_hits = 0;
        sets[s].region_hits = 0;
        sets[s].locality = LOC_UNKNOWN;
        sets[s].rng.seed(s * 9876 + 54321);
    }
}

// Periodically classify set locality
void update_locality(SetMeta& sm) {
    // Every REUSE_WINDOW accesses, update locality
    if (sm.access_time % REUSE_WINDOW == 0 && sm.access_time > 0) {
        float reuse_ratio = (float)sm.reuse_hits / (float)REUSE_WINDOW;
        float region_ratio = (float)sm.region_hits / (float)REUSE_WINDOW;
        if (region_ratio > 0.6)
            sm.locality = LOC_SPATIAL;
        else if (reuse_ratio > 0.25)
            sm.locality = LOC_REUSE;
        else
            sm.locality = LOC_RANDOM;
        sm.reuse_hits = 0;
        sm.region_hits = 0;
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
        // Evict block outside current region, then lowest reuse_score, then highest srrip
        int best_score = -10000;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            int score = 0;
            if (!sm.blocks[w].valid) score += 100;
            if (sm.blocks[w].region != curr_region) score += 10;
            score -= sm.blocks[w].reuse_score * 2;
            score -= sm.blocks[w].srrip;
            if (score > best_score) {
                best_score = score;
                victim = w;
            }
        }
    } else if (sm.locality == LOC_REUSE) {
        // Evict block with lowest reuse_score, then highest srrip
        int best_score = -10000;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            int score = 0;
            if (!sm.blocks[w].valid) score += 100;
            score -= sm.blocks[w].reuse_score * 3;
            score -= sm.blocks[w].srrip;
            if (score > best_score) {
                best_score = score;
                victim = w;
            }
        }
    } else {
        // LOC_RANDOM: SRRIP + random tie-breaking
        uint8_t max_srrip = 0;
        std::vector<uint32_t> candidates;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (!sm.blocks[w].valid) {
                victim = w;
                break;
            }
            if (sm.blocks[w].srrip > max_srrip) {
                max_srrip = sm.blocks[w].srrip;
                candidates.clear();
                candidates.push_back(w);
            } else if (sm.blocks[w].srrip == max_srrip) {
                candidates.push_back(w);
            }
        }
        if (candidates.size() > 1) {
            std::uniform_int_distribution<uint32_t> dist(0, candidates.size() - 1);
            victim = candidates[dist(sm.rng)];
        }
    }
    // Track evicted address for reuse detection
    BlockMeta &evict_block = sm.blocks[victim];
    if (evict_block.valid) {
        sm.evicted_addr_time[evict_block.tag] = sm.access_time;
        // Limit map size
        if (sm.evicted_addr_time.size() > 64)
            sm.evicted_addr_time.erase(sm.evicted_addr_time.begin());
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
    sm.access_time++;

    uint64_t curr_region = region_id(paddr);

    // Region hit detection
    if (bm.valid && bm.region == curr_region) sm.region_hits++;

    // Reuse detection: was this addr recently evicted?
    auto it = sm.evicted_addr_time.find(paddr);
    if (it != sm.evicted_addr_time.end() && (sm.access_time - it->second) <= REUSE_WINDOW) {
        sm.reuse_hits++;
        bm.reuse_score = std::min<uint8_t>(bm.reuse_score + 2, REUSE_SCORE_MAX);
        sm.evicted_addr_time.erase(it);
    }

    if (hit) {
        bm.srrip = 0; // MRU on hit
        bm.reuse_score = std::min<uint8_t>(bm.reuse_score + 1, REUSE_SCORE_MAX);
    } else {
        // Insert policy depends on locality
        if (sm.locality == LOC_SPATIAL) {
            bm.srrip = 1;
            bm.reuse_score = 2;
        } else if (sm.locality == LOC_REUSE) {
            bm.srrip = 2;
            bm.reuse_score = 1;
        } else {
            bm.srrip = SRRIP_MAX;
            bm.reuse_score = 0;
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
            std::cout << "[S:" << (int)sets[s].blocks[w].srrip
                << ",R:" << (int)sets[s].blocks[w].reuse_score
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