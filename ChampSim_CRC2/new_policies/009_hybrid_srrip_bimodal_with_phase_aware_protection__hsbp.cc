#include <vector>
#include <cstdint>
#include <iostream>
#include <cmath>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP parameters
constexpr int RRIP_BITS = 2;
constexpr int RRIP_MAX = (1 << RRIP_BITS) - 1; // 3
constexpr int RRIP_LONG = RRIP_MAX; // Insert with 3 for streaming/pointer-chasing
constexpr int RRIP_SHORT = 0;       // Insert with 0 for regular

// Phase detection
constexpr int PHASE_WINDOW = 64;
constexpr int SPATIAL_NEIGHBORHOOD = 2;
constexpr int STREAMING_THRESHOLD = 40; // % spatial hits

struct LineState {
    uint64_t tag = 0;
    uint8_t rrip = RRIP_MAX;
    bool valid = false;
};

struct SetState {
    std::vector<LineState> lines;
    std::vector<uint64_t> recent_addrs;
    uint32_t access_ptr = 0;
    uint32_t spatial_hits = 0;
    uint32_t total_accesses = 0;
    bool streaming_phase = false;
    uint32_t hits = 0;
    uint32_t misses = 0;
};

std::vector<SetState> sets(LLC_SETS);

uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

void InitReplacementState() {
    for (auto& set : sets) {
        set.lines.resize(LLC_WAYS);
        for (auto& line : set.lines) {
            line.tag = 0;
            line.rrip = RRIP_MAX;
            line.valid = false;
        }
        set.recent_addrs.resize(PHASE_WINDOW, 0);
        set.access_ptr = 0;
        set.spatial_hits = 0;
        set.total_accesses = 0;
        set.streaming_phase = false;
        set.hits = 0;
        set.misses = 0;
    }
    total_hits = total_misses = total_evictions = 0;
}

// Phase detection: streaming/stencil vs irregular
void UpdatePhase(SetState& s, uint64_t paddr) {
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

    // Every PHASE_WINDOW accesses, update streaming phase
    if (s.total_accesses % PHASE_WINDOW == 0) {
        int percent_spatial = (100 * s.spatial_hits) / PHASE_WINDOW;
        s.streaming_phase = (percent_spatial >= STREAMING_THRESHOLD);
        s.spatial_hits = 0;
    }
}

// Find victim using SRRIP, prefer invalid, else highest RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState& s = sets[set];
    UpdatePhase(s, paddr);

    // 1. Prefer invalid lines
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!s.lines[way].valid)
            return way;
    }

    // 2. SRRIP: Find line with RRIP_MAX
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.lines[way].rrip == RRIP_MAX)
                return way;
        }
        // Increment RRIP of all lines (aging)
        for (auto& line : s.lines)
            if (line.rrip < RRIP_MAX) line.rrip++;
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
    uint64_t line_addr = paddr >> 6;

    if (hit) { total_hits++; s.hits++; }
    else { total_misses++; total_evictions++; s.misses++; }

    // On hit: promote line (set RRIP to 0)
    if (hit) {
        line.rrip = RRIP_SHORT;
        line.tag = line_addr;
        line.valid = true;
        return;
    }

    // On miss: phase-aware insertion
    // Streaming/pointer-chasing: insert with RRIP_MAX (likely dead soon)
    // Else: insert with RRIP_SHORT (likely reused soon)
    if (s.streaming_phase) {
        line.rrip = RRIP_LONG;
    } else {
        line.rrip = RRIP_SHORT;
    }
    line.tag = line_addr;
    line.valid = true;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "HSBP: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}