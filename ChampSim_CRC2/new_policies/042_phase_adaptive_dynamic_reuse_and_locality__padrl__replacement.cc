#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

#define MAX_RRPV 3
#define INSERT_RRPV 2
#define MAX_REUSE 7
#define NEIGHBOR_WINDOW 2 // Number of blocks to check for spatial locality

// Per-block metadata
struct PADRL_BlockMeta {
    uint8_t valid;
    uint64_t tag;
    uint8_t rrpv;
    uint8_t reuse;     // Reuse counter (0-7)
};

// Per-set phase detector
struct PADRL_SetState {
    std::vector<PADRL_BlockMeta> meta;
    // Phase detector stats
    uint32_t recent_spatial_hits;   // Hits where neighbor block was present
    uint32_t recent_irregular_misses; // Misses with no spatial locality
    uint32_t recent_accesses;
    uint8_t current_phase; // 0 = irregular, 1 = spatial
};

std::vector<PADRL_SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, MAX_RRPV, 0});
        set.recent_spatial_hits = 0;
        set.recent_irregular_misses = 0;
        set.recent_accesses = 0;
        set.current_phase = 1; // Start optimistic: spatial
    }
}

// --- Helper: check spatial locality in set ---
bool check_neighbor_locality(uint32_t set, uint64_t tag) {
    // Check if nearby blocks in the set have similar tags (spatial locality)
    PADRL_SetState& s = sets[set];
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (s.meta[way].valid) {
            uint64_t block_tag = s.meta[way].tag;
            if (std::abs((int64_t)tag - (int64_t)block_tag) <= NEIGHBOR_WINDOW)
                return true;
        }
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
    PADRL_SetState& s = sets[set];

    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (!current_set[way].valid)
            return way;
    }

    // Phase-aware victim selection
    if (s.current_phase == 1) { // Spatial phase
        // Prefer victim with MAX_RRPV and lowest reuse, but keep neighbor blocks
        uint32_t victim = LLC_WAYS;
        uint8_t min_reuse = MAX_REUSE + 1;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (s.meta[way].rrpv == MAX_RRPV) {
                // Protect blocks with neighbor locality
                bool neighbor = check_neighbor_locality(set, s.meta[way].tag);
                if (!neighbor && s.meta[way].reuse < min_reuse) {
                    victim = way;
                    min_reuse = s.meta[way].reuse;
                }
            }
        }
        if (victim != LLC_WAYS)
            return victim;
    } else { // Irregular phase
        // Prefer victim with MAX_RRPV and lowest reuse
        uint32_t victim = LLC_WAYS;
        uint8_t min_reuse = MAX_REUSE + 1;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (s.meta[way].rrpv == MAX_RRPV && s.meta[way].reuse < min_reuse) {
                victim = way;
                min_reuse = s.meta[way].reuse;
            }
        }
        if (victim != LLC_WAYS)
            return victim;
    }

    // If none, increment all RRPVs and try again
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        s.meta[way].rrpv = std::min<uint8_t>(MAX_RRPV, s.meta[way].rrpv + 1);
    // Recursive call is safe: will terminate
    return GetVictimInSet(cpu, set, current_set, PC, paddr, type);
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
    PADRL_SetState& s = sets[set];
    uint64_t tag = paddr >> 6;
    s.recent_accesses++;

    if (hit) {
        // On hit: promote block, increment reuse
        s.meta[way].rrpv = 0;
        s.meta[way].reuse = std::min<uint8_t>(MAX_REUSE, s.meta[way].reuse + 1);
        // Phase detector: spatial hit if neighbor locality
        if (check_neighbor_locality(set, tag))
            s.recent_spatial_hits++;
    } else {
        // On fill: phase-aware insertion
        bool neighbor = check_neighbor_locality(set, tag);

        // Adaptive bypass: in irregular phase, bypass if no neighbor and reuse is low
        if (s.current_phase == 0 && !neighbor) {
            // Simulate bypass by marking invalid
            s.meta[way].valid = 0;
            s.meta[way].tag = 0;
            s.meta[way].rrpv = MAX_RRPV;
            s.meta[way].reuse = 0;
            s.recent_irregular_misses++;
            return;
        }

        // Otherwise, insert normally
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].reuse = 1;
        s.meta[way].rrpv = neighbor ? INSERT_RRPV : MAX_RRPV;

        // Phase detector: irregular miss if no neighbor
        if (!neighbor)
            s.recent_irregular_misses++;
    }

    // --- Phase adaptation every 128 accesses ---
    if ((s.recent_accesses & 0x7F) == 0) {
        // If spatial hits > irregular misses, switch to spatial phase
        if (s.recent_spatial_hits > s.recent_irregular_misses)
            s.current_phase = 1;
        else
            s.current_phase = 0;
        // Decay stats
        s.recent_spatial_hits = s.recent_spatial_hits / 2;
        s.recent_irregular_misses = s.recent_irregular_misses / 2;
    }
}

// --- Stats ---
void PrintStats() {
    uint64_t total_hits = 0, total_misses = 0, total_bypassed = 0;
    for (const auto& set : sets) {
        for (const auto& block : set.meta) {
            if (block.valid)
                total_hits += block.reuse - 1;
            total_misses += block.valid ? 1 : 0;
            if (!block.valid)
                total_bypassed++;
        }
    }
    double hitrate = (total_hits * 100.0) / (total_hits + total_misses + 1e-5);
    std::cout << "PADRL: Hits=" << total_hits << " Misses=" << total_misses
              << " Bypassed=" << total_bypassed
              << " HitRate=" << hitrate << "%" << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}