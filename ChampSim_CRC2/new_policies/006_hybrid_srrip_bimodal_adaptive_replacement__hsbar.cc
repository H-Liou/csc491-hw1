#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int MAX_RRPV = 3;      // 2-bit RRPV (SRRIP)
constexpr int BMD_WINDOW = 128;  // Window size for bimodal miss/hit tracking
constexpr int BMD_THRESHOLD = 96; // If misses in window > threshold, treat as irregular

struct LineState {
    uint8_t rrpv; // SRRIP-style re-reference prediction value (0=likely reuse, MAX_RRPV=unlikely)
};

struct SetState {
    uint32_t window_hits;
    uint32_t window_misses;
    uint32_t window_ptr;
    std::vector<uint8_t> recent_misses; // Circular buffer for last BMD_WINDOW accesses
    bool irregular_phase; // True if set is in irregular (pointer-chasing) phase
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Telemetry
uint64_t total_evictions = 0;
uint64_t srrip_evictions = 0;
uint64_t bimodal_evictions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].rrpv = MAX_RRPV; // Insert with distant reuse by default
        }
        set_states[set].window_hits = 0;
        set_states[set].window_misses = 0;
        set_states[set].window_ptr = 0;
        set_states[set].recent_misses.assign(BMD_WINDOW, 0);
        set_states[set].irregular_phase = false;
    }
}

// SRRIP victim selection: evict line with MAX_RRPV, else increment all RRPVs and retry
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    auto& lstates = line_states[set];
    auto& sstate = set_states[set];

    // First, try to find a line with RRPV == MAX_RRPV
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].rrpv == MAX_RRPV) {
            if (sstate.irregular_phase)
                bimodal_evictions++;
            else
                srrip_evictions++;
            total_evictions++;
            return way;
        }
    }
    // If none found, increment all RRPVs and retry
    for (int way = 0; way < LLC_WAYS; ++way)
        if (lstates[way].rrpv < MAX_RRPV)
            lstates[way].rrpv++;
    // Now, at least one should be MAX_RRPV
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].rrpv == MAX_RRPV) {
            if (sstate.irregular_phase)
                bimodal_evictions++;
            else
                srrip_evictions++;
            total_evictions++;
            return way;
        }
    }
    // Fallback: evict way 0
    total_evictions++;
    return 0;
}

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
    auto& sstate = set_states[set];
    auto& lstates = line_states[set][way];

    // --- Update bimodal window ---
    sstate.recent_misses[sstate.window_ptr] = hit ? 0 : 1;
    sstate.window_ptr = (sstate.window_ptr + 1) % BMD_WINDOW;
    // Count misses in window
    int miss_count = 0;
    for (int i = 0; i < BMD_WINDOW; ++i)
        miss_count += sstate.recent_misses[i];
    sstate.irregular_phase = (miss_count > BMD_THRESHOLD);

    // --- SRRIP update ---
    if (hit) {
        lstates.rrpv = 0; // On hit, set to MRU (likely reuse soon)
        sstate.window_hits++;
    } else {
        // On miss, insert with different RRPV depending on phase
        sstate.window_misses++;
        if (sstate.irregular_phase) {
            // Pointer-chasing/irregular: insert with MAX_RRPV (evict quickly)
            lstates.rrpv = MAX_RRPV;
        } else {
            // Regular: insert with MAX_RRPV-1 (retain longer)
            lstates.rrpv = MAX_RRPV - 1;
        }
    }
}

void PrintStats() {
    std::cout << "HSBAR: Total evictions: " << total_evictions << std::endl;
    std::cout << "HSBAR: SRRIP (regular) evictions: " << srrip_evictions << std::endl;
    std::cout << "HSBAR: Bimodal (irregular) evictions: " << bimodal_evictions << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "HSBAR heartbeat: evictions=" << total_evictions
              << " srrip_evictions=" << srrip_evictions
              << " bimodal_evictions=" << bimodal_evictions << std::endl;
}