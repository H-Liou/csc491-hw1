#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int ACCESS_HISTORY = 4;    // Number of access intervals tracked per line
constexpr int REUSE_THRESHOLD = 2;   // Minimum short intervals to be considered reusable
constexpr int INTERVAL_SHORT = 32;   // Cycles: short reuse interval threshold

struct LineState {
    uint8_t lru_position;                    // 0 = MRU, LLC_WAYS-1 = LRU
    std::vector<uint64_t> access_timestamps; // Last ACCESS_HISTORY timestamps
    uint8_t hit_history;                     // Bitmask of last 4 accesses (1=hit, 0=miss)
    bool reusable;                           // Is this line classified as reusable?
    uint64_t tag;                            // For debugging
};

struct SetState {
    uint32_t window_hits;
    uint32_t window_misses;
    uint64_t last_timestamp;                 // For interval calculation
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Telemetry
uint64_t total_evictions = 0;
uint64_t transient_evictions = 0;
uint64_t reusable_evictions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].lru_position = way;
            line_states[set][way].access_timestamps.assign(ACCESS_HISTORY, 0);
            line_states[set][way].hit_history = 0;
            line_states[set][way].reusable = false;
            line_states[set][way].tag = 0;
        }
        set_states[set].window_hits = 0;
        set_states[set].window_misses = 0;
        set_states[set].last_timestamp = 0;
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    auto& lstates = line_states[set];

    // First, try to evict a transient (non-reusable) line with highest LRU position
    int victim = -1;
    uint8_t max_lru = 0;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (!lstates[way].reusable) {
            if (victim == -1 || lstates[way].lru_position > max_lru) {
                victim = way;
                max_lru = lstates[way].lru_position;
            }
        }
    }
    if (victim != -1) {
        transient_evictions++;
        total_evictions++;
        return victim;
    }

    // Otherwise, evict the most LRU among reusable lines
    victim = 0;
    max_lru = lstates[0].lru_position;
    for (int way = 1; way < LLC_WAYS; ++way) {
        if (lstates[way].lru_position > max_lru) {
            victim = way;
            max_lru = lstates[way].lru_position;
        }
    }
    reusable_evictions++;
    total_evictions++;
    return victim;
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

    // --- Window hit/miss tracking for phase detection (optional, for stats) ---
    if (hit) sstate.window_hits++;
    else     sstate.window_misses++;

    // --- LRU update ---
    uint8_t old_pos = lstates.lru_position;
    for (int w = 0; w < LLC_WAYS; ++w) {
        if (w == way) continue;
        if (line_states[set][w].lru_position < old_pos)
            line_states[set][w].lru_position++;
    }
    lstates.lru_position = 0;

    // --- Access interval tracking ---
    uint64_t curr_time = sstate.last_timestamp + 1;
    sstate.last_timestamp = curr_time;
    // Shift timestamps, insert current
    for (int i = ACCESS_HISTORY - 1; i > 0; --i)
        lstates.access_timestamps[i] = lstates.access_timestamps[i-1];
    lstates.access_timestamps[0] = curr_time;

    // --- Hit/miss history tracking ---
    lstates.hit_history = ((lstates.hit_history << 1) | (hit ? 1 : 0)) & 0xF;

    // --- Reuse classification ---
    int short_intervals = 0;
    for (int i = 1; i < ACCESS_HISTORY; ++i) {
        if (lstates.access_timestamps[i] == 0) continue;
        uint64_t interval = lstates.access_timestamps[i-1] - lstates.access_timestamps[i];
        if (interval <= INTERVAL_SHORT) short_intervals++;
    }
    // If enough short intervals or repeated hits, mark reusable
    if (short_intervals >= REUSE_THRESHOLD || (lstates.hit_history & 0xE) == 0xE) {
        lstates.reusable = true;
    } else {
        lstates.reusable = false;
    }

    // --- Save tag for debugging ---
    lstates.tag = paddr >> 6;
}

void PrintStats() {
    std::cout << "DRPR: Total evictions: " << total_evictions << std::endl;
    std::cout << "DRPR: Transient (non-reusable) evictions: " << transient_evictions << std::endl;
    std::cout << "DRPR: Reusable evictions: " << reusable_evictions << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "DRPR heartbeat: evictions=" << total_evictions
              << " transient_evictions=" << transient_evictions
              << " reusable_evictions=" << reusable_evictions << std::endl;
}