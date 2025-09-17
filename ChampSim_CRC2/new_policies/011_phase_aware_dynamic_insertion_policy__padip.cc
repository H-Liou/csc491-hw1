#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int RRIP_BITS = 2;
constexpr int RRIP_MAX = (1 << RRIP_BITS) - 1; // 3
constexpr int RRIP_LONG = RRIP_MAX; // Insert with 3 for streaming
constexpr int RRIP_SHORT = 0;       // Insert with 0 for reuse
constexpr int RRIP_MID = 1;         // Insert with 1 for spatial

// Phase detection parameters
constexpr int PHASE_WINDOW = 64; // accesses per set before re-evaluating phase
constexpr int STREAMING_THRESHOLD = 52; // misses in window to be streaming
constexpr int SPATIAL_STRIDE_WINDOW = 8; // accesses to detect stride
constexpr int SPATIAL_STRIDE_MATCH = 6;  // matches to be spatial

struct LineState {
    uint64_t tag = 0;
    uint8_t rrip = RRIP_MAX;
    bool valid = false;
};

struct SetState {
    std::vector<LineState> lines;
    // Phase tracking
    uint32_t access_count = 0;
    uint32_t miss_count = 0;
    uint32_t last_addr = 0;
    std::vector<uint32_t> recent_strides;
    bool is_streaming = false;
    bool is_spatial = false;
};

std::vector<SetState> sets(LLC_SETS);

uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

// --- Initialization ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.lines.resize(LLC_WAYS);
        for (auto& line : set.lines) {
            line.tag = 0;
            line.rrip = RRIP_MAX;
            line.valid = false;
        }
        set.access_count = 0;
        set.miss_count = 0;
        set.last_addr = 0;
        set.recent_strides.clear();
        set.is_streaming = false;
        set.is_spatial = false;
    }
    total_hits = total_misses = total_evictions = 0;
}

// --- Victim Selection (SRRIP) ---
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
        if (!s.lines[way].valid)
            return way;
    }
    // SRRIP: Find RRIP_MAX
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.lines[way].rrip == RRIP_MAX)
                return way;
        }
        // Age all lines
        for (auto& line : s.lines)
            if (line.rrip < RRIP_MAX) line.rrip++;
    }
}

// --- Phase Detection Helper ---
void UpdatePhase(SetState& s, uint64_t curr_addr, bool miss) {
    s.access_count++;
    if (miss) s.miss_count++;

    // Detect streaming: many misses in window
    if (s.access_count >= PHASE_WINDOW) {
        s.is_streaming = (s.miss_count >= STREAMING_THRESHOLD);
        s.access_count = 0;
        s.miss_count = 0;
    }

    // Detect spatial: stride pattern in recent accesses
    if (s.last_addr != 0) {
        uint32_t stride = static_cast<uint32_t>(curr_addr - s.last_addr);
        if (stride != 0) {
            s.recent_strides.push_back(stride);
            if (s.recent_strides.size() > SPATIAL_STRIDE_WINDOW)
                s.recent_strides.erase(s.recent_strides.begin());
        }
        // If enough strides match, spatial detected
        if (s.recent_strides.size() == SPATIAL_STRIDE_WINDOW) {
            uint32_t most_common = 0, max_count = 0;
            for (auto val : s.recent_strides) {
                uint32_t cnt = std::count(s.recent_strides.begin(), s.recent_strides.end(), val);
                if (cnt > max_count) {
                    max_count = cnt;
                    most_common = val;
                }
            }
            s.is_spatial = (max_count >= SPATIAL_STRIDE_MATCH);
        }
    }
    s.last_addr = curr_addr;
}

// --- Replacement State Update ---
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

    // Stats
    if (hit) total_hits++;
    else { total_misses++; total_evictions++; }

    // Update phase detector
    UpdatePhase(s, line_addr, !hit);

    // On hit: promote
    if (hit) {
        line.rrip = RRIP_SHORT;
        line.tag = line_addr;
        line.valid = true;
        return;
    }

    // On miss: insertion policy based on phase
    if (line.valid) {
        // No extra bookkeeping needed
    }

    // Streaming phase: insert with RRIP_LONG (evict quickly)
    // Spatial phase: insert with RRIP_MID (retain for spatial reuse)
    // Otherwise: insert with RRIP_SHORT (temporal reuse)
    if (s.is_streaming) {
        line.rrip = RRIP_LONG;
    } else if (s.is_spatial) {
        line.rrip = RRIP_MID;
    } else {
        line.rrip = RRIP_SHORT;
    }
    line.tag = line_addr;
    line.valid = true;
}

// --- Stats ---
void PrintStats() {
    std::cout << "PADIP: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}