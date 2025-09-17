#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DSRL parameters
#define DSRL_SIG_SIZE 8
#define DSRL_FREQ_MAX 15
#define DSRL_SPATIAL_RADIUS 2
#define DSRL_PHASE_WIN 32

struct DSRLBlockMeta {
    uint8_t valid;
    uint64_t tag;
    uint8_t lru;         // LRU position
    uint8_t freq;        // Reuse counter
    uint32_t last_sig;   // Last access signature (hash of PC and addr)
    uint8_t spatial_score;
};

struct DSRLSetState {
    std::array<uint64_t, DSRL_SIG_SIZE> recent_addrs;
    std::array<uint32_t, DSRL_SIG_SIZE> recent_sigs;
    uint32_t win_ptr;
    uint32_t stride;
    uint8_t stride_valid;
    uint32_t hits;
    uint32_t misses;
    std::vector<DSRLBlockMeta> meta;

    // Phase detection
    std::array<uint8_t, DSRL_PHASE_WIN> phase_hits;
    std::array<uint8_t, DSRL_PHASE_WIN> phase_misses;
    uint32_t phase_ptr;
};

std::vector<DSRLSetState> sets(LLC_SETS);

// --- Helper: compute spatial locality and stride ---
void update_spatial_stride(DSRLSetState& s, uint64_t curr_addr) {
    // Compute stride from last address
    uint64_t prev_addr = s.recent_addrs[(s.win_ptr + DSRL_SIG_SIZE - 1) % DSRL_SIG_SIZE];
    if (prev_addr != 0) {
        uint64_t stride = std::abs(int64_t(curr_addr - prev_addr));
        if (stride > 0 && stride < 64) {
            s.stride = stride;
            s.stride_valid = 1;
        } else {
            s.stride_valid = 0;
        }
    }
}

// --- Helper: signature hash ---
uint32_t dsrl_sig_hash(uint64_t PC, uint64_t addr) {
    // Simple CRC32 hash
    return champsim_crc32(addr ^ PC);
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, 0, 0, 0, 0});
        set.recent_addrs.fill(0);
        set.recent_sigs.fill(0);
        set.win_ptr = 0;
        set.stride = 0;
        set.stride_valid = 0;
        set.hits = 0;
        set.misses = 0;
        set.phase_hits.fill(0);
        set.phase_misses.fill(0);
        set.phase_ptr = 0;
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
    DSRLSetState& s = sets[set];
    uint64_t curr_addr = paddr >> 6;
    uint32_t curr_sig = dsrl_sig_hash(PC, curr_addr);

    // Prefer invalid blocks first
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }

    // Phase detection: compute hit ratio over last window
    uint32_t phase_hits = std::accumulate(s.phase_hits.begin(), s.phase_hits.end(), 0);
    uint32_t phase_misses = std::accumulate(s.phase_misses.begin(), s.phase_misses.end(), 0);
    float hit_ratio = (phase_hits + phase_misses) ? (float(phase_hits) / (phase_hits + phase_misses)) : 0.0f;

    // If stride is valid and hit ratio is high, prefer spatial eviction (streaming/regular)
    if (s.stride_valid && hit_ratio > 0.4f) {
        // Evict block farthest from current stride window
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

    // Otherwise, use signature-based reuse (irregular/pointer-heavy)
    // Evict block with lowest frequency and lowest signature match
    uint8_t min_freq = DSRL_FREQ_MAX + 1;
    uint32_t min_sig_match = UINT32_MAX;
    uint8_t max_lru = 0;
    uint32_t victim = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        uint32_t sig_match = (s.meta[way].last_sig == curr_sig) ? 0 : 1;
        if (s.meta[way].freq < min_freq ||
            (s.meta[way].freq == min_freq && sig_match > min_sig_match) ||
            (s.meta[way].freq == min_freq && sig_match == min_sig_match && s.meta[way].lru > max_lru)) {
            min_freq = s.meta[way].freq;
            min_sig_match = sig_match;
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
    DSRLSetState& s = sets[set];
    uint64_t tag = paddr >> 6;
    uint32_t sig = dsrl_sig_hash(PC, tag);

    // Update recent address and signature history
    s.recent_addrs[s.win_ptr] = tag;
    s.recent_sigs[s.win_ptr] = sig;
    s.win_ptr = (s.win_ptr + 1) % DSRL_SIG_SIZE;
    update_spatial_stride(s, tag);

    // Update phase stats
    s.phase_hits[s.phase_ptr] = hit ? 1 : 0;
    s.phase_misses[s.phase_ptr] = hit ? 0 : 1;
    s.phase_ptr = (s.phase_ptr + 1) % DSRL_PHASE_WIN;

    // Update hit/miss counters
    if (hit) s.hits++; else s.misses++;

    // Update LRU for all valid blocks
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (s.meta[w].valid)
            s.meta[w].lru = std::min<uint8_t>(255, s.meta[w].lru + 1);
    }

    if (hit) {
        s.meta[way].lru = 0;
        s.meta[way].freq = std::min<uint8_t>(DSRL_FREQ_MAX, s.meta[way].freq + 1);
        s.meta[way].last_sig = sig;
    } else {
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].lru = 0;
        s.meta[way].freq = 1;
        s.meta[way].last_sig = sig;
    }
}

// --- Stats ---
void PrintStats() {
    uint64_t total_hits = 0, total_misses = 0;
    for (const auto& s : sets) {
        total_hits += s.hits;
        total_misses += s.misses;
    }
    std::cout << "DSRL: Hits=" << total_hits << " Misses=" << total_misses
              << " HitRate=" << (total_hits * 100.0 / (total_hits + total_misses)) << "%" << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}