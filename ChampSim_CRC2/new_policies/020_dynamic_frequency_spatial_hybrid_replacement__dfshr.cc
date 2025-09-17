#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

#define REGION_SIZE 512
#define PHASE_WINDOW 128
#define REGION_HIT_THRESH 0.6
#define FREQ_HIT_THRESH 0.25

enum PhaseType { PHASE_UNKNOWN = 0, PHASE_SPATIAL = 1, PHASE_FREQ = 2 };

struct BlockMeta {
    uint64_t tag;
    uint32_t freq;      // access frequency
    uint64_t region;    // region id
    bool valid;
};

struct SetMeta {
    std::vector<BlockMeta> blocks;
    uint32_t access_time;
    uint32_t region_hits;
    uint32_t freq_hits;
    PhaseType phase;
    uint64_t last_region;
    uint32_t last_freq_block;
};

std::vector<SetMeta> sets(LLC_SETS);

inline uint64_t region_id(uint64_t paddr) {
    return paddr / REGION_SIZE;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].tag = 0;
            sets[s].blocks[w].freq = 0;
            sets[s].blocks[w].region = 0;
            sets[s].blocks[w].valid = false;
        }
        sets[s].access_time = 0;
        sets[s].region_hits = 0;
        sets[s].freq_hits = 0;
        sets[s].phase = PHASE_UNKNOWN;
        sets[s].last_region = 0;
        sets[s].last_freq_block = 0;
    }
}

// Periodically classify set phase
void update_phase(SetMeta& sm, uint64_t curr_region) {
    // Every PHASE_WINDOW accesses, update phase
    if (sm.access_time % PHASE_WINDOW == 0 && sm.access_time > 0) {
        float region_ratio = (float)sm.region_hits / (float)PHASE_WINDOW;
        float freq_ratio = (float)sm.freq_hits / (float)PHASE_WINDOW;
        if (region_ratio > REGION_HIT_THRESH)
            sm.phase = PHASE_SPATIAL;
        else if (freq_ratio > FREQ_HIT_THRESH)
            sm.phase = PHASE_FREQ;
        else
            sm.phase = PHASE_UNKNOWN;
        sm.region_hits = 0;
        sm.freq_hits = 0;
    }

    // Region hit: any block in set matches curr_region
    for (const auto& b : sm.blocks)
        if (b.valid && b.region == curr_region) { sm.region_hits++; break; }

    // Freq hit: any block in set has freq >= 2 (recent reuse)
    for (const auto& b : sm.blocks)
        if (b.valid && b.freq >= 2) { sm.freq_hits++; break; }
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
    uint64_t curr_region = region_id(paddr);
    update_phase(sm, curr_region);

    uint32_t victim = 0;

    if (sm.phase == PHASE_SPATIAL) {
        // Evict block outside current region, then lowest freq, then invalid
        int best_score = -100000;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            int score = 0;
            if (!sm.blocks[w].valid) score += 10000;
            if (sm.blocks[w].region != curr_region) score += 100;
            score -= sm.blocks[w].freq; // prefer lower freq
            if (score > best_score) {
                best_score = score;
                victim = w;
            }
        }
    } else if (sm.phase == PHASE_FREQ) {
        // Evict block with lowest freq, then invalid, then outside region
        int min_freq = 1000000;
        std::vector<uint32_t> candidates;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (!sm.blocks[w].valid) {
                victim = w;
                return victim;
            }
            if (sm.blocks[w].freq < min_freq) {
                min_freq = sm.blocks[w].freq;
                candidates.clear();
                candidates.push_back(w);
            } else if (sm.blocks[w].freq == min_freq) {
                candidates.push_back(w);
            }
        }
        // Tie-break: prefer block outside current region
        for (auto w : candidates) {
            if (sm.blocks[w].region != curr_region) {
                victim = w;
                return victim;
            }
        }
        victim = candidates[0];
    } else {
        // Unknown phase: fallback to LRU (lowest freq, oldest)
        int min_freq = 1000000;
        uint32_t min_idx = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (!sm.blocks[w].valid) {
                victim = w;
                return victim;
            }
            if (sm.blocks[w].freq < min_freq) {
                min_freq = sm.blocks[w].freq;
                min_idx = w;
            }
        }
        victim = min_idx;
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

    if (hit) {
        bm.freq++;
    } else {
        bm.freq = 1;
    }
    bm.tag = paddr;
    bm.region = curr_region;
    bm.valid = true;
}

// Print end-of-simulation statistics
void PrintStats() {
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " phase: " << sets[s].phase << " | ";
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            std::cout << "[F:" << sets[s].blocks[w].freq
                << ",R:" << sets[s].blocks[w].region
                << ",V:" << sets[s].blocks[w].valid << "] ";
        }
        std::cout << "\n";
    }
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}