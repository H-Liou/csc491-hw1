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

// Phase detection window
#define PHASE_WINDOW 32
#define PHASE_HIGH_REUSE_THRESHOLD 0.5 // >50% hits in window = high reuse phase

struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
    uint8_t reuse; // Block-level reuse counter
};

struct SetState {
    std::vector<BlockMeta> meta;
    std::array<uint8_t, PHASE_WINDOW> recent_hits; // 1=hit, 0=miss
    uint32_t window_ptr;
    float phase_score; // Fraction of hits in window
    bool high_reuse_phase; // true: retain blocks, false: evict aggressively
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0, 0});
        set.recent_hits.fill(0);
        set.window_ptr = 0;
        set.phase_score = 0.0f;
        set.high_reuse_phase = true;
    }
}

// --- Helper: update phase window and score ---
void update_phase(SetState& s, uint8_t hit) {
    s.recent_hits[s.window_ptr] = hit ? 1 : 0;
    s.window_ptr = (s.window_ptr + 1) % PHASE_WINDOW;
    // Recompute phase score every window
    if (s.window_ptr == 0) {
        uint32_t hits = 0;
        for (auto v : s.recent_hits) hits += v;
        s.phase_score = float(hits) / PHASE_WINDOW;
        s.high_reuse_phase = (s.phase_score >= PHASE_HIGH_REUSE_THRESHOLD);
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
    SetState& s = sets[set];

    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }

    // Phase-adaptive victim selection
    // High reuse phase: SRRIP (evict highest RRIP, break ties with lowest reuse)
    // Streaming/irregular phase: LFU (evict lowest reuse, break ties with highest RRIP)
    uint32_t victim = 0;
    if (s.high_reuse_phase) {
        uint8_t max_rrip = 0;
        uint8_t min_reuse = REUSE_MAX+1;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip >= max_rrip) {
                if (s.meta[way].reuse < min_reuse ||
                    (s.meta[way].reuse == min_reuse && s.meta[way].rrip > max_rrip)) {
                    victim = way;
                    max_rrip = s.meta[way].rrip;
                    min_reuse = s.meta[way].reuse;
                }
            }
        }
    } else {
        uint8_t min_reuse = REUSE_MAX+1;
        uint8_t max_rrip = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].reuse <= min_reuse) {
                if (s.meta[way].rrip > max_rrip ||
                    (s.meta[way].rrip == max_rrip && s.meta[way].reuse < min_reuse)) {
                    victim = way;
                    min_reuse = s.meta[way].reuse;
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

    // --- Update phase window ---
    update_phase(s, hit);

    // --- Block reuse counter ---
    if (hit) {
        s.meta[way].reuse = std::min<uint8_t>(REUSE_MAX, s.meta[way].reuse + 1);
        s.meta[way].rrip = RRIP_LONG; // promote on hit
    } else {
        s.meta[way].reuse = 1; // new block starts at 1
        // Insert with phase-adaptive RRIP
        if (s.high_reuse_phase)
            s.meta[way].rrip = RRIP_LONG; // retain if set shows reuse
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
    std::cout << "DRPAR: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}