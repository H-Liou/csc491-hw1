#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_INSERT_LONG (RRIP_MAX - 1)
#define RRIP_INSERT_SHORT RRIP_MAX

// BIP constants
#define BIP_PROB 32 // 1/32 blocks inserted long, rest short

// LFU constants
#define LFU_MAX 15

// Phase detection
#define PHASE_WIN 32
#define REGULAR_THRESHOLD 0.6 // >60% hits = regular
#define STREAM_THRESHOLD 0.2  // <20% hits = streaming

enum PhaseType { PHASE_REGULAR, PHASE_STREAM, PHASE_IRREGULAR };

struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
    uint8_t lfu; // Block-level LFU counter
};

struct SetState {
    std::vector<BlockMeta> meta;
    std::array<uint8_t, PHASE_WIN> recent_hits; // 1=hit, 0=miss
    uint32_t window_ptr;
    float hit_rate; // Fraction of hits in window
    PhaseType phase;
    uint32_t bip_counter; // For BIP probabilistic insertion
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0, 0});
        set.recent_hits.fill(0);
        set.window_ptr = 0;
        set.hit_rate = 0.0f;
        set.phase = PHASE_REGULAR;
        set.bip_counter = 0;
    }
}

// --- Helper: update phase based on hit/miss window ---
void update_phase(SetState& s, uint8_t hit) {
    s.recent_hits[s.window_ptr] = hit ? 1 : 0;
    s.window_ptr = (s.window_ptr + 1) % PHASE_WIN;
    // Recompute hit rate at window boundary
    if (s.window_ptr == 0) {
        uint32_t hits = 0;
        for (auto v : s.recent_hits) hits += (v == 1);
        s.hit_rate = float(hits) / PHASE_WIN;
        if (s.hit_rate >= REGULAR_THRESHOLD)
            s.phase = PHASE_REGULAR;
        else if (s.hit_rate <= STREAM_THRESHOLD)
            s.phase = PHASE_STREAM;
        else
            s.phase = PHASE_IRREGULAR;
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

    // Victim selection based on phase
    uint32_t victim = 0;
    if (s.phase == PHASE_REGULAR) {
        // SRRIP: evict block with highest RRIP
        uint8_t max_rrip = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip >= max_rrip) {
                victim = way;
                max_rrip = s.meta[way].rrip;
            }
        }
    } else if (s.phase == PHASE_STREAM) {
        // BIP: evict block with highest RRIP (blocks inserted with short RRIP)
        uint8_t max_rrip = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip >= max_rrip) {
                victim = way;
                max_rrip = s.meta[way].rrip;
            }
        }
    } else {
        // LFU: evict block with lowest LFU, break ties with highest RRIP
        uint8_t min_lfu = LFU_MAX + 1;
        uint8_t max_rrip = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].lfu < min_lfu ||
                (s.meta[way].lfu == min_lfu && s.meta[way].rrip > max_rrip)) {
                victim = way;
                min_lfu = s.meta[way].lfu;
                max_rrip = s.meta[way].rrip;
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

    // --- Block-level LFU counter ---
    if (hit) {
        s.meta[way].lfu = std::min<uint8_t>(LFU_MAX, s.meta[way].lfu + 1);
        s.meta[way].rrip = 0; // promote on hit
    } else {
        s.meta[way].lfu = 1; // new block starts at 1
        // Phase-adaptive RRIP insertion
        if (s.phase == PHASE_REGULAR) {
            s.meta[way].rrip = RRIP_INSERT_LONG; // SRRIP: retain
        } else if (s.phase == PHASE_STREAM) {
            // BIP: Insert with RRIP_SHORT except 1 in BIP_PROB
            if (s.bip_counter == 0)
                s.meta[way].rrip = RRIP_INSERT_LONG;
            else
                s.meta[way].rrip = RRIP_INSERT_SHORT;
            s.bip_counter = (s.bip_counter + 1) % BIP_PROB;
        } else {
            // LFU: Insert with RRIP_SHORT (evict soon unless reused)
            s.meta[way].rrip = RRIP_INSERT_SHORT;
        }
    }

    // --- Valid/tag update ---
    s.meta[way].valid = 1;
    s.meta[way].tag = tag;
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "DPAR: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}