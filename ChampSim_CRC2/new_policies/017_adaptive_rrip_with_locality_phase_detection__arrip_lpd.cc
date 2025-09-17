#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_LONG 2   // Insert with 2 for normal, 3 for low-locality
#define RRIP_SHORT 0  // Insert with 0 for high-locality

// Per-block metadata
struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;    // 0=MRU, 3=LRU
    uint64_t tag;
};

// Per-set phase detector
struct SetState {
    std::vector<BlockMeta> meta;
    uint64_t last_addr;
    int64_t last_stride;
    uint32_t spatial_hits;
    uint32_t spatial_total;
    bool spatial_phase; // true = regular stride detected
    uint32_t temporal_hits;
    uint32_t temporal_total;
    bool temporal_phase; // true = frequent reuse detected
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0});
        set.last_addr = 0;
        set.last_stride = 0;
        set.spatial_hits = 0;
        set.spatial_total = 0;
        set.spatial_phase = false;
        set.temporal_hits = 0;
        set.temporal_total = 0;
        set.temporal_phase = false;
    }
}

// --- Per-set spatial and temporal locality detector ---
void UpdatePhase(SetState& s, uint64_t paddr, bool hit, uint64_t tag) {
    // Spatial phase: stride detection
    s.spatial_total++;
    int64_t stride = paddr - s.last_addr;
    if (s.last_addr && stride == s.last_stride && stride != 0)
        s.spatial_hits++;
    s.last_stride = stride;
    s.last_addr = paddr;
    if (s.spatial_total >= 256) {
        s.spatial_phase = (s.spatial_hits * 100 / s.spatial_total) > 60;
        s.spatial_hits = 0;
        s.spatial_total = 0;
    }
    // Temporal phase: reuse detection
    s.temporal_total++;
    if (hit)
        s.temporal_hits++;
    if (s.temporal_total >= 256) {
        s.temporal_phase = (s.temporal_hits * 100 / s.temporal_total) > 40;
        s.temporal_hits = 0;
        s.temporal_total = 0;
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
    // Prefer invalid
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }
    // Standard RRIP victim selection: pick block(s) with RRIP_MAX
    for (uint32_t round = 0; round < 2; round++) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip == RRIP_MAX)
                return way;
        }
        // If none found, increment all RRIP values (aging)
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip < RRIP_MAX)
                s.meta[way].rrip++;
        }
    }
    // Fallback: evict LRU (highest RRIP)
    uint32_t victim = 0;
    uint8_t max_rrip = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.meta[way].rrip >= max_rrip) {
            max_rrip = s.meta[way].rrip;
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
    SetState& s = sets[set];
    uint64_t tag = paddr >> 6;
    UpdatePhase(s, paddr, hit, tag);

    // On hit: promote block (set RRIP to 0)
    if (hit) {
        s.meta[way].rrip = 0;
    } else {
        // On miss/insertion: adapt insertion RRIP based on detected phase
        if (s.spatial_phase || s.temporal_phase) {
            // High spatial or temporal locality: retain longer
            s.meta[way].rrip = RRIP_SHORT;
        } else {
            // Low locality: insert with long RRIP (quick eviction)
            s.meta[way].rrip = RRIP_LONG;
        }
    }
    s.meta[way].valid = 1;
    s.meta[way].tag = tag;
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "ARRIP-LPD: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}