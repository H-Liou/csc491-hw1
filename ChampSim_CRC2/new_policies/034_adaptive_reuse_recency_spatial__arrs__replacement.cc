#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ARRS parameters
#define ARRS_FREQ_MAX 15
#define ARRS_SPATIAL_RADIUS 2
#define ARRS_HIST_WIN 8

struct ARRSBlockMeta {
    uint8_t valid;
    uint64_t tag;
    uint8_t lru;   // LRU position
    uint8_t freq;  // Reuse counter
};

struct ARRSSetState {
    std::array<uint64_t, ARRS_HIST_WIN> recent_addrs;
    uint32_t win_ptr;
    float spatial_locality;
    uint32_t hits;
    uint32_t misses;
    std::vector<ARRSBlockMeta> meta;
};

std::vector<ARRSSetState> sets(LLC_SETS);

// --- Helper: compute spatial locality ---
float compute_spatial_locality(const ARRSSetState& s, uint64_t curr_addr) {
    uint32_t spatial_hits = 0;
    for (uint32_t i = 0; i < ARRS_HIST_WIN; ++i) {
        if (std::abs(int64_t(curr_addr - s.recent_addrs[i])) <= ARRS_SPATIAL_RADIUS)
            spatial_hits++;
    }
    return float(spatial_hits) / ARRS_HIST_WIN;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, 0, 0});
        set.recent_addrs.fill(0);
        set.win_ptr = 0;
        set.spatial_locality = 0.0f;
        set.hits = 0;
        set.misses = 0;
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
    ARRSSetState& s = sets[set];

    // Prefer invalid blocks first
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }

    // Compute spatial locality for current access
    uint64_t curr_addr = paddr >> 6;
    s.spatial_locality = compute_spatial_locality(s, curr_addr);

    // If spatial locality is high, prefer evicting blocks farthest from current address
    if (s.spatial_locality > 0.5f) {
        int64_t max_dist = -1;
        uint8_t max_lru = 0;
        uint32_t victim = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            int64_t dist = std::abs(int64_t(s.meta[way].tag - curr_addr));
            if (dist > max_dist || (dist == max_dist && s.meta[way].lru > max_lru)) {
                max_dist = dist;
                max_lru = s.meta[way].lru;
                victim = way;
            }
        }
        return victim;
    }

    // Otherwise, combine recency and frequency (reuse)
    // Evict block with lowest frequency, break ties with highest LRU
    uint8_t min_freq = ARRS_FREQ_MAX + 1;
    uint8_t max_lru = 0;
    uint32_t victim = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.meta[way].freq < min_freq ||
            (s.meta[way].freq == min_freq && s.meta[way].lru > max_lru)) {
            min_freq = s.meta[way].freq;
            max_lru = s.meta[way].lru;
            victim = way;
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
    ARRSSetState& s = sets[set];
    uint64_t tag = paddr >> 6;

    // Update recent address history
    s.recent_addrs[s.win_ptr] = tag;
    s.win_ptr = (s.win_ptr + 1) % ARRS_HIST_WIN;

    // Update hit/miss stats
    if (hit) s.hits++; else s.misses++;

    // Update LRU for all valid blocks
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (s.meta[w].valid)
            s.meta[w].lru = std::min<uint8_t>(255, s.meta[w].lru + 1);
    }

    if (hit) {
        s.meta[way].lru = 0;
        s.meta[way].freq = std::min<uint8_t>(ARRS_FREQ_MAX, s.meta[way].freq + 1);
    } else {
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].lru = 0;
        s.meta[way].freq = 1;
    }
}

// --- Stats ---
void PrintStats() {
    uint64_t total_hits = 0, total_misses = 0;
    for (const auto& s : sets) {
        total_hits += s.hits;
        total_misses += s.misses;
    }
    std::cout << "ARRS: Hits=" << total_hits << " Misses=" << total_misses
              << " HitRate=" << (total_hits * 100.0 / (total_hits + total_misses)) << "%" << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}