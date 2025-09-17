#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- STAR parameters ---
#define STAR_RECENT_WIN 32
#define STAR_SPATIAL_RADIUS 2 // Neighbor blocks within +/-2 lines
#define STAR_FREQ_MAX 15
#define STAR_PC_ENTROPY_WIN 8
#define STAR_STREAM_THRESHOLD 0.18
#define STAR_SPATIAL_THRESHOLD 0.5

enum STARPhase { STAR_REGULAR, STAR_SPATIAL, STAR_STREAM, STAR_IRREGULAR };

struct STARBlockMeta {
    uint8_t valid;
    uint64_t tag;
    uint8_t recency; // LRU-style counter
    uint8_t freq;    // Frequency counter
};

struct STARSetState {
    std::vector<STARBlockMeta> meta;
    std::array<uint64_t, STAR_RECENT_WIN> recent_addrs;
    std::array<uint8_t, STAR_RECENT_WIN> recent_hits;
    uint32_t win_ptr;
    float hit_rate;
    float spatial_locality;
    STARPhase phase;
    std::array<uint64_t, STAR_PC_ENTROPY_WIN> recent_pcs;
    uint32_t pc_ptr;
};

std::vector<STARSetState> sets(LLC_SETS);

// --- Helper: compute spatial locality in window ---
float compute_spatial_locality(const STARSetState& s) {
    uint32_t spatial_hits = 0;
    for (uint32_t i = 0; i < STAR_RECENT_WIN; ++i) {
        uint64_t addr = s.recent_addrs[i];
        for (uint32_t j = 0; j < STAR_RECENT_WIN; ++j) {
            if (i == j) continue;
            uint64_t other = s.recent_addrs[j];
            if (std::abs(int64_t(addr - other)) <= STAR_SPATIAL_RADIUS) {
                spatial_hits++;
                break;
            }
        }
    }
    return float(spatial_hits) / STAR_RECENT_WIN;
}

// --- Helper: compute PC entropy (for pointer-chasing detection) ---
float compute_pc_entropy(const STARSetState& s) {
    std::array<uint64_t, STAR_PC_ENTROPY_WIN> pcs = s.recent_pcs;
    std::sort(pcs.begin(), pcs.end());
    uint32_t unique = std::unique(pcs.begin(), pcs.end()) - pcs.begin();
    return float(unique) / STAR_PC_ENTROPY_WIN;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, 0, 0});
        set.recent_addrs.fill(0);
        set.recent_hits.fill(0);
        set.win_ptr = 0;
        set.hit_rate = 0.0f;
        set.spatial_locality = 0.0f;
        set.phase = STAR_REGULAR;
        set.recent_pcs.fill(0);
        set.pc_ptr = 0;
    }
}

// --- Phase detection ---
void update_phase(STARSetState& s, uint64_t paddr, uint64_t PC, uint8_t hit) {
    s.recent_addrs[s.win_ptr] = paddr >> 6;
    s.recent_hits[s.win_ptr] = hit ? 1 : 0;
    s.win_ptr = (s.win_ptr + 1) % STAR_RECENT_WIN;
    s.recent_pcs[s.pc_ptr] = PC;
    s.pc_ptr = (s.pc_ptr + 1) % STAR_PC_ENTROPY_WIN;

    // Recompute at window boundary
    if (s.win_ptr == 0) {
        uint32_t hits = 0;
        for (auto v : s.recent_hits) hits += v;
        s.hit_rate = float(hits) / STAR_RECENT_WIN;
        s.spatial_locality = compute_spatial_locality(s);

        float pc_entropy = compute_pc_entropy(s);

        if (s.hit_rate < STAR_STREAM_THRESHOLD)
            s.phase = STAR_STREAM;
        else if (s.spatial_locality > STAR_SPATIAL_THRESHOLD)
            s.phase = STAR_SPATIAL;
        else if (pc_entropy > 0.8)
            s.phase = STAR_IRREGULAR;
        else
            s.phase = STAR_REGULAR;
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
    STARSetState& s = sets[set];

    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }

    uint32_t victim = 0;
    if (s.phase == STAR_SPATIAL) {
        // Retain blocks with addresses close to current paddr, evict farthest
        uint64_t curr_addr = paddr >> 6;
        int64_t max_dist = -1;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            int64_t dist = std::abs(int64_t(s.meta[way].tag - curr_addr));
            if (dist > max_dist) {
                max_dist = dist;
                victim = way;
            }
        }
    } else if (s.phase == STAR_STREAM) {
        // Streaming: evict block with oldest recency (LRU)
        uint8_t max_recency = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].recency >= max_recency) {
                max_recency = s.meta[way].recency;
                victim = way;
            }
        }
    } else if (s.phase == STAR_IRREGULAR) {
        // Pointer-heavy: evict block with lowest frequency, break ties with recency
        uint8_t min_freq = STAR_FREQ_MAX + 1;
        uint8_t max_recency = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].freq < min_freq ||
                (s.meta[way].freq == min_freq && s.meta[way].recency > max_recency)) {
                min_freq = s.meta[way].freq;
                max_recency = s.meta[way].recency;
                victim = way;
            }
        }
    } else {
        // Regular: evict block with oldest recency, prefer lowest frequency
        uint8_t max_recency = 0;
        uint8_t min_freq = STAR_FREQ_MAX + 1;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if ((s.meta[way].recency > max_recency) ||
                (s.meta[way].recency == max_recency && s.meta[way].freq < min_freq)) {
                max_recency = s.meta[way].recency;
                min_freq = s.meta[way].freq;
                victim = way;
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
    STARSetState& s = sets[set];
    uint64_t tag = paddr >> 6;

    // --- Update phase ---
    update_phase(s, paddr, PC, hit);

    // --- Update block metadata ---
    // Update recency for all blocks (increment, cap at 255)
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (s.meta[w].valid)
            s.meta[w].recency = std::min<uint8_t>(255, s.meta[w].recency + 1);
    }

    if (hit) {
        s.meta[way].recency = 0; // Most recent
        s.meta[way].freq = std::min<uint8_t>(STAR_FREQ_MAX, s.meta[way].freq + 1);
    } else {
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].recency = 0;
        s.meta[way].freq = 1; // New block starts at freq=1
    }
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "STAR: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}