#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Reuse counter and RRIP constants
#define REUSE_MAX 7
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_LONG 0
#define RRIP_SHORT RRIP_MAX

// Streaming detection window
#define STREAM_WIN 32
#define STREAM_THRESHOLD 0.8 // >80% misses = streaming/irregular phase

// For spatial locality: track last N block addresses per set
#define SPATIAL_TRACK 4

struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
    uint8_t reuse; // Block-level reuse counter
    uint8_t spatial; // Spatial locality score (0-3)
};

struct SetState {
    std::vector<BlockMeta> meta;
    std::array<uint8_t, STREAM_WIN> recent_hits; // 1=hit, 0=miss
    uint32_t window_ptr;
    float stream_score; // Fraction of misses in window
    bool streaming_phase; // true: streaming/irregular, false: regular
    std::array<uint64_t, SPATIAL_TRACK> recent_addrs; // Track last N block addresses
    uint32_t spatial_ptr;
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0, 0, 0});
        set.recent_hits.fill(0);
        set.window_ptr = 0;
        set.stream_score = 0.0f;
        set.streaming_phase = false;
        set.recent_addrs.fill(0);
        set.spatial_ptr = 0;
    }
}

// --- Helper: update streaming window and score ---
void update_stream(SetState& s, uint8_t hit) {
    s.recent_hits[s.window_ptr] = hit ? 1 : 0;
    s.window_ptr = (s.window_ptr + 1) % STREAM_WIN;
    // Recompute stream score every window
    if (s.window_ptr == 0) {
        uint32_t misses = 0;
        for (auto v : s.recent_hits) misses += (v == 0);
        s.stream_score = float(misses) / STREAM_WIN;
        s.streaming_phase = (s.stream_score >= STREAM_THRESHOLD);
    }
}

// --- Helper: update spatial locality score ---
uint8_t compute_spatial(SetState& s, uint64_t block_addr) {
    // Score is # of matches with recent addresses (excluding self)
    uint8_t score = 0;
    for (uint32_t i = 0; i < SPATIAL_TRACK; i++) {
        if (s.recent_addrs[i] && s.recent_addrs[i] != block_addr) {
            // If within +/-2 blocks, count as spatially local
            if (std::abs(int64_t(s.recent_addrs[i]) - int64_t(block_addr)) <= 2)
                score++;
        }
    }
    return score;
}

void update_spatial(SetState& s, uint64_t block_addr) {
    s.recent_addrs[s.spatial_ptr] = block_addr;
    s.spatial_ptr = (s.spatial_ptr + 1) % SPATIAL_TRACK;
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
    SetState& s = sets[set];

    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }

    // Victim selection:
    // Regular phase: evict highest RRIP, break ties with lowest reuse+spatial
    // Streaming phase: evict lowest reuse+spatial, break ties with highest RRIP
    uint32_t victim = 0;
    if (!s.streaming_phase) {
        uint8_t max_rrip = 0;
        uint8_t min_sum = REUSE_MAX + 4 + 1;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            uint8_t sum = s.meta[way].reuse + s.meta[way].spatial;
            if (s.meta[way].rrip >= max_rrip) {
                if (sum < min_sum ||
                    (sum == min_sum && s.meta[way].rrip > max_rrip)) {
                    victim = way;
                    max_rrip = s.meta[way].rrip;
                    min_sum = sum;
                }
            }
        }
    } else {
        uint8_t min_sum = REUSE_MAX + 4 + 1;
        uint8_t max_rrip = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            uint8_t sum = s.meta[way].reuse + s.meta[way].spatial;
            if (sum <= min_sum) {
                if (s.meta[way].rrip > max_rrip ||
                    (s.meta[way].rrip == max_rrip && sum < min_sum)) {
                    victim = way;
                    min_sum = sum;
                    max_rrip = s.meta[way].rrip;
                }
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
    SetState& s = sets[set];
    uint64_t tag = paddr >> 6;
    uint64_t block_addr = (paddr >> 6); // block granularity

    // --- Update streaming window ---
    update_stream(s, hit);

    // --- Update spatial locality ---
    uint8_t spatial_score = compute_spatial(s, block_addr);
    update_spatial(s, block_addr);

    // --- Block reuse counter ---
    if (hit) {
        s.meta[way].reuse = std::min<uint8_t>(REUSE_MAX, s.meta[way].reuse + 1);
        s.meta[way].rrip = RRIP_LONG; // promote on hit
        s.meta[way].spatial = std::min<uint8_t>(3, spatial_score + 1);
    } else {
        s.meta[way].reuse = 1; // new block starts at 1
        s.meta[way].spatial = spatial_score; // inherit spatial score
        // Insert with phase-adaptive RRIP
        if (!s.streaming_phase)
            s.meta[way].rrip = RRIP_LONG; // retain if regular phase
        else
            s.meta[way].rrip = RRIP_SHORT; // evict soon in streaming/irregular phase
    }

    // --- Valid/tag update ---
    s.meta[way].valid = 1;
    s.meta[way].tag = tag;
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "MSLAR: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}