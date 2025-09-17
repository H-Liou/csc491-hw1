#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

#define REGION_SIZE 512
#define PRED_HISTORY_LEN 32
#define SCORE_MAX 15
#define SCORE_MIN 0
#define REGION_BOOST 4

struct BlockMeta {
    uint64_t tag;
    uint64_t region;
    uint8_t score;   // cache-friendliness score
    bool valid;
    uint64_t pc_sig; // lower bits of PC for predictor
};

struct SetMeta {
    std::vector<BlockMeta> blocks;
    std::vector<uint64_t> recent_evicted_pc; // history of evicted PC sigs
    std::vector<uint64_t> recent_hit_pc;     // history of hit PC sigs
};

std::vector<SetMeta> sets(LLC_SETS);

inline uint64_t region_id(uint64_t paddr) {
    return paddr / REGION_SIZE;
}

inline uint64_t pc_sig(uint64_t PC) {
    // Use lower 12 bits as PC signature
    return PC & 0xFFF;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].tag = 0;
            sets[s].blocks[w].region = 0;
            sets[s].blocks[w].score = SCORE_MIN;
            sets[s].blocks[w].valid = false;
            sets[s].blocks[w].pc_sig = 0;
        }
        sets[s].recent_evicted_pc.clear();
        sets[s].recent_hit_pc.clear();
    }
}

// Simple predictor: if PC sig seen in recent hits > evicts, consider cache-friendly
bool is_cache_friendly(SetMeta& sm, uint64_t pc_sig) {
    int hit_count = std::count(sm.recent_hit_pc.begin(), sm.recent_hit_pc.end(), pc_sig);
    int evict_count = std::count(sm.recent_evicted_pc.begin(), sm.recent_evicted_pc.end(), pc_sig);
    return hit_count >= evict_count;
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

    // Prefer to evict blocks with lowest score, tie-break: not in current region
    int min_score = SCORE_MAX + 1;
    std::vector<uint32_t> candidates;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (!sm.blocks[w].valid) {
            return w; // prefer invalid
        }
        int score = sm.blocks[w].score;
        if (score < min_score) {
            min_score = score;
            candidates.clear();
            candidates.push_back(w);
        } else if (score == min_score) {
            candidates.push_back(w);
        }
    }
    // Among candidates, prefer block not in current region
    for (auto w : candidates) {
        if (sm.blocks[w].region != curr_region)
            return w;
    }
    // Otherwise, evict first candidate
    return candidates[0];
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
    uint64_t curr_region = region_id(paddr);
    uint64_t curr_pc_sig = pc_sig(PC);

    // On hit: boost score, record hit PC
    if (hit) {
        bm.score = std::min<uint8_t>(bm.score + 2, SCORE_MAX);
        if (sm.recent_hit_pc.size() >= PRED_HISTORY_LEN)
            sm.recent_hit_pc.erase(sm.recent_hit_pc.begin());
        sm.recent_hit_pc.push_back(curr_pc_sig);
    } else {
        // On miss: set score based on predictor
        if (is_cache_friendly(sm, curr_pc_sig))
            bm.score = std::min<uint8_t>(bm.score + 1, SCORE_MAX);
        else
            bm.score = std::max<uint8_t>(bm.score - 1, SCORE_MIN);
    }

    // Region boost: if in same region as current access, boost score
    if (bm.region == curr_region)
        bm.score = std::min<uint8_t>(bm.score + REGION_BOOST, SCORE_MAX);

    bm.tag = paddr;
    bm.region = curr_region;
    bm.valid = true;
    bm.pc_sig = curr_pc_sig;

    // Track evicted PC
    if (!hit) {
        if (sm.recent_evicted_pc.size() >= PRED_HISTORY_LEN)
            sm.recent_evicted_pc.erase(sm.recent_evicted_pc.begin());
        sm.recent_evicted_pc.push_back(curr_pc_sig);
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " block scores: ";
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            std::cout << "[S:" << (int)sets[s].blocks[w].score
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