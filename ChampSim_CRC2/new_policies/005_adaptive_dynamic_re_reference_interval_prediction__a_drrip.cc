#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
constexpr int RRPV_MAX = 3;    // 2-bit RRPV
constexpr int RRPV_LONG = RRPV_MAX;    // "Long" insertion (low reuse)
constexpr int RRPV_SHORT = RRPV_MAX - 1; // "Short" insertion (high reuse)
constexpr int POLICY_SRRIP = 0;
constexpr int POLICY_BRRIP = 1;

// Per-set phase detection
constexpr int PHASE_WINDOW = 64;
constexpr int SPATIAL_NEIGHBORHOOD = 2; // +/-2 lines for spatial locality
constexpr int SPATIAL_HIT_THRESHOLD = 18; // >=18/64 accesses are spatial = streaming

struct LineState {
    uint64_t tag = 0;
    uint8_t rrpv = RRPV_MAX;
};

struct SetState {
    std::vector<LineState> lines;
    // Phase detection
    std::vector<uint64_t> recent_addrs;
    uint32_t access_ptr = 0;
    uint32_t spatial_hits = 0;
    uint32_t total_accesses = 0;
    bool spatial_mode = false;
    // DRRIP policy selection
    uint8_t drrip_policy = POLICY_SRRIP;
    uint32_t hit_count = 0;
    uint32_t miss_count = 0;
};

std::vector<SetState> sets(LLC_SETS);

// Stats
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

void InitReplacementState() {
    for (auto& set : sets) {
        set.lines.resize(LLC_WAYS);
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            set.lines[way].tag = 0;
            set.lines[way].rrpv = RRPV_MAX;
        }
        set.recent_addrs.resize(PHASE_WINDOW, 0);
        set.access_ptr = 0;
        set.spatial_hits = 0;
        set.total_accesses = 0;
        set.spatial_mode = false;
        set.drrip_policy = POLICY_SRRIP;
        set.hit_count = 0;
        set.miss_count = 0;
    }
    total_hits = total_misses = total_evictions = 0;
}

// Helper: phase detection for spatial locality
void UpdateSpatialMode(SetState& s, uint64_t paddr) {
    uint64_t line_addr = paddr >> 6;
    // Check for spatial hit (neighbor within +/-2 lines)
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
    }
}

// Helper: DRRIP policy selection based on recent miss/hit ratio
void UpdateDRRIPPolicy(SetState& s) {
    // Every 256 accesses, adjust policy
    const int POLICY_WINDOW = 256;
    if ((s.hit_count + s.miss_count) >= POLICY_WINDOW) {
        double miss_rate = double(s.miss_count) / (s.hit_count + s.miss_count);
        // If miss rate high, use BRRIP (long insertion, evict more aggressively)
        // If miss rate low, use SRRIP (short insertion, retain lines longer)
        if (miss_rate > 0.35)
            s.drrip_policy = POLICY_BRRIP;
        else
            s.drrip_policy = POLICY_SRRIP;
        s.hit_count = 0;
        s.miss_count = 0;
    }
}

// Find victim in the set using RRPV
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
    UpdateDRRIPPolicy(s);

    // Standard SRRIP/BRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.lines[way].rrpv == RRPV_MAX)
                return way;
        }
        // Increment RRPV for all lines (aging)
        for (uint32_t way = 0; way < LLC_WAYS; way++)
            if (s.lines[way].rrpv < RRPV_MAX)
                s.lines[way].rrpv++;
    }
}

// Update replacement state after access
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

    line.tag = paddr >> 6;

    // Insertion policy: adapt based on phase and DRRIP policy
    if (!hit) {
        // If spatial mode, always use SRRIP (short insertion)
        if (s.spatial_mode)
            line.rrpv = RRPV_SHORT;
        else if (s.drrip_policy == POLICY_SRRIP)
            line.rrpv = RRPV_SHORT;
        else
            line.rrpv = RRPV_LONG;
    } else {
        // On hit, reset RRPV (high reuse)
        line.rrpv = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "A-DRRIP+: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}