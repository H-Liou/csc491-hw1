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
#define REUSE_MAX 7
#define FREQ_MAX 15
#define SPATIAL_STRIDE 64
#define SPATIAL_WINDOW 6
#define FREQ_DECAY_INTERVAL 8192 // Decay frequency counters every N accesses

struct BlockMeta {
    uint64_t tag;
    uint8_t lru;        // LRU stack position (0 = MRU)
    uint8_t reuse;      // Recent reuse counter (temporal locality)
    uint8_t freq;       // Frequency counter (long-term access)
    bool spatial;       // Spatially correlated
};

struct SetMeta {
    std::vector<BlockMeta> blocks;
    std::vector<uint64_t> stride_hist; // Recent strides for spatial detection
    uint64_t last_addr; // Last accessed address for stride calculation
    uint64_t access_count; // For frequency decay
};

std::vector<SetMeta> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].tag = 0;
            sets[s].blocks[w].lru = w;
            sets[s].blocks[w].reuse = 0;
            sets[s].blocks[w].freq = 0;
            sets[s].blocks[w].spatial = false;
        }
        sets[s].stride_hist.clear();
        sets[s].last_addr = 0;
        sets[s].access_count = 0;
    }
}

// --- Helper: detect spatial correlation based on recent strides ---
bool detect_spatial(uint64_t paddr, SetMeta& sm) {
    if (sm.stride_hist.empty()) return false;
    uint64_t stride = std::abs((int64_t)paddr - (int64_t)sm.last_addr);
    for (auto s : sm.stride_hist) {
        if (std::abs((int64_t)stride - (int64_t)s) <= SPATIAL_STRIDE)
            return true;
    }
    return false;
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

    // Score each block: lower score = better eviction candidate
    // Score = (reuse * 2) + (freq) + (spatial ? -2 : 0) + (lru)
    // - If spatial correlation, reduce score (prefer to keep spatial blocks)
    // - Favor blocks with low reuse and frequency
    // - Use LRU as tiebreaker

    uint32_t victim = 0;
    int min_score = 10000;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        int score = (int)sets[set].blocks[w].reuse * 2
                  + (int)sets[set].blocks[w].freq
                  + (sets[set].blocks[w].spatial ? -2 : 0)
                  + (int)sets[set].blocks[w].lru;
        // Penalize blocks with tag==0 (empty), favoring them for eviction
        if (sets[set].blocks[w].tag == 0)
            score -= 5;
        if (score < min_score) {
            min_score = score;
            victim = w;
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

    // Update stride history for spatial detection
    uint64_t stride = (sm.last_addr == 0) ? 0 : std::abs((int64_t)paddr - (int64_t)sm.last_addr);
    if (stride != 0) {
        sm.stride_hist.push_back(stride);
        if (sm.stride_hist.size() > SPATIAL_WINDOW)
            sm.stride_hist.erase(sm.stride_hist.begin());
    }
    sm.last_addr = paddr;

    // Detect spatial correlation for current block
    bm.spatial = detect_spatial(paddr, sm);

    // Update reuse counter (temporal locality)
    if (hit)
        bm.reuse = std::min<uint8_t>(bm.reuse + 1, REUSE_MAX);
    else
        bm.reuse = 0;

    // Update frequency counter (long-term locality)
    bm.freq = std::min<uint8_t>(bm.freq + 1, FREQ_MAX);

    // Decay all frequency counters every FREQ_DECAY_INTERVAL accesses
    sm.access_count++;
    if (sm.access_count % FREQ_DECAY_INTERVAL == 0) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (sm.blocks[w].freq > 0)
                sm.blocks[w].freq--;
        }
    }

    // Update LRU stack
    uint8_t old_lru = bm.lru;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (sm.blocks[w].lru < old_lru)
            sm.blocks[w].lru++;
    }
    bm.lru = 0;

    // On miss, insert block with spatial correlation at MRU, else at LRU
    if (!hit) {
        if (bm.spatial)
            bm.lru = 0;
        else
            bm.lru = LLC_WAYS - 1;
        bm.reuse = 0;
        bm.freq = 1;
    }

    // Update tag
    bm.tag = paddr;
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    // Print LRU, reuse, freq, spatial for first 4 sets
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << ": ";
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            std::cout << "[L:" << (int)sets[s].blocks[w].lru
                      << ",R:" << (int)sets[s].blocks[w].reuse
                      << ",F:" << (int)sets[s].blocks[w].freq
                      << ",S:" << (int)sets[s].blocks[w].spatial << "] ";
        }
        std::cout << "\n";
    }
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    // No-op
}