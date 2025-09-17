#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata ---
struct BlockMeta {
    uint8_t valid;
    uint8_t lru_position; // 0 = MRU, LLC_WAYS-1 = LRU
    uint8_t freq_counter; // 0-7
    uint64_t tag;         // For block identification
};

// --- Per-set stride detector ---
struct SetState {
    std::vector<BlockMeta> meta;
    uint64_t last_addr;
    int64_t last_stride;
    uint32_t spatial_hits;
    uint32_t spatial_total;
    bool spatial_phase;
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, 0, 0});
        set.last_addr = 0;
        set.last_stride = 0;
        set.spatial_hits = 0;
        set.spatial_total = 0;
        set.spatial_phase = false;
    }
}

// --- Per-set spatial locality detector ---
void UpdateSpatialPhase(SetState& s, uint64_t paddr) {
    s.spatial_total++;
    int64_t stride = paddr - s.last_addr;
    if (s.last_addr && stride == s.last_stride && stride != 0)
        s.spatial_hits++;
    s.last_stride = stride;
    s.last_addr = paddr;
    // Update phase every 256 accesses
    if (s.spatial_total >= 256) {
        s.spatial_phase = (s.spatial_hits * 100 / s.spatial_total) > 60;
        s.spatial_hits = 0;
        s.spatial_total = 0;
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
    // Composite score: lower is worse (more likely to be evicted)
    // score = 2*LRU + (7-freq) - 2*spatial_phase
    uint32_t victim = 0;
    int min_score = 1000;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        int score = 2 * s.meta[way].lru_position + (7 - s.meta[way].freq_counter);
        if (s.spatial_phase)
            score -= 2; // spatial phase: keep blocks longer
        if (score < min_score) {
            min_score = score;
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
    UpdateSpatialPhase(s, paddr);

    // Update frequency counter
    if (hit) {
        if (s.meta[way].freq_counter < 7)
            s.meta[way].freq_counter++;
    } else {
        s.meta[way].freq_counter = 1; // new block starts with freq 1
    }

    // Update LRU stack
    uint8_t old_pos = s.meta[way].lru_position;
    for (uint32_t i = 0; i < LLC_WAYS; i++) {
        if (!s.meta[i].valid) continue;
        if (s.meta[i].lru_position < old_pos)
            s.meta[i].lru_position++;
    }
    s.meta[way].lru_position = 0;
    s.meta[way].valid = 1;
    s.meta[way].tag = paddr >> 6; // block tag
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "DMFR: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}