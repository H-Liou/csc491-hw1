#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// PADR parameters
#define PADR_HIST_WIN 16
#define PADR_SPATIAL_RADIUS 2
#define PADR_FREQ_MAX 15
#define PADR_STREAM_HITRATE_TH 0.20
#define PADR_SPATIAL_LOCALITY_TH 0.5
#define PADR_PC_ENTROPY_TH 0.75

enum PADRPhase { PADR_STREAM, PADR_SPATIAL, PADR_IRREGULAR, PADR_REGULAR };

struct PADRBlockMeta {
    uint8_t valid;
    uint64_t tag;
    uint8_t recency; // LRU-style counter
    uint8_t freq;    // Frequency counter
};

struct PADRSetState {
    std::vector<PADRBlockMeta> meta;
    std::array<uint64_t, PADR_HIST_WIN> recent_addrs;
    std::array<uint8_t, PADR_HIST_WIN> recent_hits;
    std::array<uint64_t, PADR_HIST_WIN> recent_pcs;
    uint32_t win_ptr;
    PADRPhase phase;
    float hit_rate;
    float spatial_locality;
    float pc_entropy;
};

std::vector<PADRSetState> sets(LLC_SETS);

// --- Helper: compute spatial locality ---
float compute_spatial_locality(const PADRSetState& s) {
    uint32_t spatial_hits = 0;
    for (uint32_t i = 0; i < PADR_HIST_WIN; ++i) {
        uint64_t addr = s.recent_addrs[i];
        for (uint32_t j = 0; j < PADR_HIST_WIN; ++j) {
            if (i == j) continue;
            uint64_t other = s.recent_addrs[j];
            if (std::abs(int64_t(addr - other)) <= PADR_SPATIAL_RADIUS) {
                spatial_hits++;
                break;
            }
        }
    }
    return float(spatial_hits) / PADR_HIST_WIN;
}

// --- Helper: compute PC entropy ---
float compute_pc_entropy(const PADRSetState& s) {
    std::array<uint64_t, PADR_HIST_WIN> pcs = s.recent_pcs;
    std::sort(pcs.begin(), pcs.end());
    uint32_t unique = std::unique(pcs.begin(), pcs.end()) - pcs.begin();
    return float(unique) / PADR_HIST_WIN;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, 0, 0});
        set.recent_addrs.fill(0);
        set.recent_hits.fill(0);
        set.recent_pcs.fill(0);
        set.win_ptr = 0;
        set.phase = PADR_REGULAR;
        set.hit_rate = 0.0f;
        set.spatial_locality = 0.0f;
        set.pc_entropy = 0.0f;
    }
}

// --- Phase detection ---
void update_phase(PADRSetState& s, uint64_t paddr, uint64_t PC, uint8_t hit) {
    s.recent_addrs[s.win_ptr] = paddr >> 6;
    s.recent_hits[s.win_ptr] = hit ? 1 : 0;
    s.recent_pcs[s.win_ptr] = PC;
    s.win_ptr = (s.win_ptr + 1) % PADR_HIST_WIN;

    // Only update phase at window boundary
    if (s.win_ptr == 0) {
        uint32_t hits = 0;
        for (auto v : s.recent_hits) hits += v;
        s.hit_rate = float(hits) / PADR_HIST_WIN;
        s.spatial_locality = compute_spatial_locality(s);
        s.pc_entropy = compute_pc_entropy(s);

        if (s.hit_rate < PADR_STREAM_HITRATE_TH)
            s.phase = PADR_STREAM;
        else if (s.spatial_locality > PADR_SPATIAL_LOCALITY_TH)
            s.phase = PADR_SPATIAL;
        else if (s.pc_entropy > PADR_PC_ENTROPY_TH)
            s.phase = PADR_IRREGULAR;
        else
            s.phase = PADR_REGULAR;
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
    PADRSetState& s = sets[set];

    // Prefer invalid blocks first
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }

    uint32_t victim = 0;
    if (s.phase == PADR_STREAM) {
        // Streaming: evict block with oldest recency (pure LRU)
        uint8_t max_recency = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].recency >= max_recency) {
                max_recency = s.meta[way].recency;
                victim = way;
            }
        }
    } else if (s.phase == PADR_SPATIAL) {
        // Spatial: evict block farthest from current address, break ties with recency
        uint64_t curr_addr = paddr >> 6;
        int64_t max_dist = -1;
        uint8_t max_recency = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            int64_t dist = std::abs(int64_t(s.meta[way].tag - curr_addr));
            if (dist > max_dist || (dist == max_dist && s.meta[way].recency > max_recency)) {
                max_dist = dist;
                max_recency = s.meta[way].recency;
                victim = way;
            }
        }
    } else if (s.phase == PADR_IRREGULAR) {
        // Irregular: evict block with lowest frequency, break ties with recency
        uint8_t min_freq = PADR_FREQ_MAX + 1;
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
        uint8_t min_freq = PADR_FREQ_MAX + 1;
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
    PADRSetState& s = sets[set];
    uint64_t tag = paddr >> 6;

    // Update phase
    update_phase(s, paddr, PC, hit);

    // Update recency for all valid blocks
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (s.meta[w].valid)
            s.meta[w].recency = std::min<uint8_t>(255, s.meta[w].recency + 1);
    }

    if (hit) {
        s.meta[way].recency = 0;
        s.meta[way].freq = std::min<uint8_t>(PADR_FREQ_MAX, s.meta[way].freq + 1);
    } else {
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].recency = 0;
        s.meta[way].freq = 1;
    }
}

// --- Stats ---
uint64_t padr_hits = 0, padr_misses = 0, padr_evictions = 0;
void PrintStats() {
    std::cout << "PADR: Hits=" << padr_hits << " Misses=" << padr_misses
              << " Evictions=" << padr_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}