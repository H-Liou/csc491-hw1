#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <cmath>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Policy parameters
constexpr int LFU_MAX = 15; // 4-bit frequency counter
constexpr int PHASE_WINDOW = 64;
constexpr int SPATIAL_NEIGHBORHOOD = 2;
constexpr int SPATIAL_HIT_THRESHOLD = 18;

// Per-line state
struct LineState {
    uint64_t tag = 0;
    uint8_t lfu = 0;     // Frequency counter
    uint8_t recency = 0; // Recency bit (0 = recently used, 1 = not)
};

// Per-set state
struct SetState {
    std::vector<LineState> lines;
    std::vector<uint64_t> recent_addrs;
    uint32_t access_ptr = 0;
    uint32_t spatial_hits = 0;
    uint32_t total_accesses = 0;
    bool spatial_mode = false; // Streaming/stencil phase
    uint32_t hit_count = 0;
    uint32_t miss_count = 0;
    uint8_t phase_policy = 0; // 0: LFU, 1: LRU, 2: Spatial
};

std::vector<SetState> sets(LLC_SETS);

// Stats
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

void InitReplacementState() {
    for (auto& set : sets) {
        set.lines.resize(LLC_WAYS);
        for (auto& line : set.lines) {
            line.tag = 0;
            line.lfu = 0;
            line.recency = 1;
        }
        set.recent_addrs.resize(PHASE_WINDOW, 0);
        set.access_ptr = 0;
        set.spatial_hits = 0;
        set.total_accesses = 0;
        set.spatial_mode = false;
        set.hit_count = 0;
        set.miss_count = 0;
        set.phase_policy = 0;
    }
    total_hits = total_misses = total_evictions = 0;
}

// Phase detection: spatial streaming/stencil
void UpdateSpatialMode(SetState& s, uint64_t paddr) {
    uint64_t line_addr = paddr >> 6;
    bool spatial_hit = false;
    for (int i = 0; i < PHASE_WINDOW; i++) {
        uint64_t prev_addr = s.recent_addrs[i];
        if (prev_addr == 0) continue;
        if (std::abs(int64_t(line_addr) - int64_t(prev_addr)) <= SPATIAL_NEIGHBORHOOD) {
            spatial_hit = true;
            break;
        }
    }
    if (spatial_hit) s.spatial_hits++;
    s.recent_addrs[s.access_ptr] = line_addr;
    s.access_ptr = (s.access_ptr + 1) % PHASE_WINDOW;
    s.total_accesses++;

    // Every PHASE_WINDOW accesses, update spatial mode
    if (s.total_accesses % PHASE_WINDOW == 0) {
        s.spatial_mode = (s.spatial_hits >= SPATIAL_HIT_THRESHOLD);
        s.spatial_hits = 0;
        // Change phase policy: spatial_mode -> spatial, else LFU or LRU
        if (s.spatial_mode)
            s.phase_policy = 2; // Spatial
        else if (s.hit_count > s.miss_count)
            s.phase_policy = 0; // LFU
        else
            s.phase_policy = 1; // LRU
        s.hit_count = 0;
        s.miss_count = 0;
    }
}

// Victim selection: hybrid
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState& s = sets[set];
    UpdateSpatialMode(s, paddr);

    // 1. If spatial phase, evict line farthest from current address (streaming/stencil)
    if (s.phase_policy == 2) {
        uint64_t line_addr = paddr >> 6;
        int max_dist = -1;
        uint32_t victim = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            int dist = std::abs(int64_t(line_addr) - int64_t(s.lines[way].tag));
            if (dist > max_dist) {
                max_dist = dist;
                victim = way;
            }
        }
        return victim;
    }

    // 2. If LFU phase, evict line with lowest frequency (ties: oldest recency)
    if (s.phase_policy == 0) {
        uint8_t min_lfu = LFU_MAX+1;
        uint32_t victim = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.lines[way].lfu < min_lfu) {
                min_lfu = s.lines[way].lfu;
                victim = way;
            } else if (s.lines[way].lfu == min_lfu && s.lines[way].recency == 1) {
                victim = way;
            }
        }
        return victim;
    }

    // 3. Else, LRU: evict line with recency bit set (not recently used)
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.lines[way].recency == 1)
            return way;
    }
    // If all recently used, pick way 0
    return 0;
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
    SetState& s = sets[set];
    LineState& line = s.lines[way];

    if (hit) { total_hits++; s.hit_count++; }
    else { total_misses++; total_evictions++; s.miss_count++; }

    uint64_t line_addr = paddr >> 6;
    line.tag = line_addr;

    // On hit: boost frequency, set recency
    if (hit) {
        if (line.lfu < LFU_MAX) line.lfu++;
        line.recency = 0;
    } else {
        // On miss: reset frequency, set recency = not recently used
        line.lfu = 1;
        line.recency = 1;
        // If spatial mode, boost frequency for spatially adjacent lines
        if (s.phase_policy == 2) {
            for (auto& l : s.lines) {
                if (std::abs(int64_t(l.tag) - int64_t(line_addr)) <= SPATIAL_NEIGHBORHOOD) {
                    if (l.lfu < LFU_MAX) l.lfu++;
                }
            }
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "HMSR: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}