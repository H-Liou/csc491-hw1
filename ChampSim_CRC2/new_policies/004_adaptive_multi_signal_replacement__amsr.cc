#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <deque>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Policy Parameters ---
constexpr int FREQ_BITS = 3;             // 3-bit saturating frequency counter
constexpr int SPATIAL_HISTORY = 8;       // Number of recent strides to track per set
constexpr int SPATIAL_MATCH = 4;         // Minimum matches to consider stride regular
constexpr int PHASE_WINDOW = 128;        // Window for phase detection
constexpr float PHASE_HIT_RATIO_HIGH = 0.50; // If hit ratio high, favor frequency
constexpr float PHASE_HIT_RATIO_LOW  = 0.20; // If hit ratio low, favor recency

struct LineState {
    uint8_t lru_position;                // 0 = MRU, LLC_WAYS-1 = LRU
    uint8_t freq_counter;                // Frequency counter
    bool spatial_boosted;                // Is this line spatially boosted?
    uint64_t tag;                        // For stride detection
};

struct SetState {
    uint32_t window_hits;
    uint32_t window_misses;
    std::deque<int64_t> stride_history;  // Recent access strides
    uint64_t last_addr;                  // Last address accessed in this set
    bool favor_freq;                     // Current phase: favor frequency or recency
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Telemetry
uint64_t total_evictions = 0;
uint64_t freq_evictions = 0;
uint64_t lru_evictions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way] = {static_cast<uint8_t>(way), 0, false, 0};
        }
        set_states[set].window_hits = 0;
        set_states[set].window_misses = 0;
        set_states[set].stride_history.clear();
        set_states[set].last_addr = 0;
        set_states[set].favor_freq = false;
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
    auto& sstate = set_states[set];
    auto& lstates = line_states[set];

    // --- Phase detection: adjust weighting between frequency and recency ---
    if ((sstate.window_hits + sstate.window_misses) >= PHASE_WINDOW) {
        float hit_ratio = float(sstate.window_hits) / float(sstate.window_hits + sstate.window_misses);
        if (hit_ratio > PHASE_HIT_RATIO_HIGH)
            sstate.favor_freq = true;
        else if (hit_ratio < PHASE_HIT_RATIO_LOW)
            sstate.favor_freq = false;
        // else keep previous
        sstate.window_hits = 0;
        sstate.window_misses = 0;
    }

    // --- Victim selection ---
    uint32_t victim = 0;
    if (sstate.favor_freq) {
        // Evict lowest frequency, break ties by LRU
        uint8_t min_freq = lstates[0].freq_counter;
        uint8_t max_lru = lstates[0].lru_position;
        victim = 0;
        for (uint32_t way = 1; way < LLC_WAYS; ++way) {
            if (lstates[way].freq_counter < min_freq ||
                (lstates[way].freq_counter == min_freq && lstates[way].lru_position > max_lru)) {
                min_freq = lstates[way].freq_counter;
                max_lru = lstates[way].lru_position;
                victim = way;
            }
        }
        freq_evictions++;
    } else {
        // Evict LRU, break ties by lowest frequency
        uint8_t max_lru = lstates[0].lru_position;
        uint8_t min_freq = lstates[0].freq_counter;
        victim = 0;
        for (uint32_t way = 1; way < LLC_WAYS; ++way) {
            if (lstates[way].lru_position > max_lru ||
                (lstates[way].lru_position == max_lru && lstates[way].freq_counter < min_freq)) {
                max_lru = lstates[way].lru_position;
                min_freq = lstates[way].freq_counter;
                victim = way;
            }
        }
        lru_evictions++;
    }
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
    auto& lstates = line_states[set];

    // --- Window miss/hit tracking for phase detection ---
    if (hit) sstate.window_hits++;
    else     sstate.window_misses++;

    // --- Stride detection for spatial locality ---
    int64_t stride = (sstate.last_addr == 0) ? 0 : (int64_t)paddr - (int64_t)sstate.last_addr;
    sstate.last_addr = paddr;
    if (stride != 0) {
        if (sstate.stride_history.size() >= SPATIAL_HISTORY)
            sstate.stride_history.pop_front();
        sstate.stride_history.push_back(stride);
    }

    // --- LRU update ---
    uint8_t old_pos = lstates[way].lru_position;
    for (int w = 0; w < LLC_WAYS; ++w) {
        if (w == way) continue;
        if (lstates[w].lru_position < old_pos)
            lstates[w].lru_position++;
    }
    lstates[way].lru_position = 0;

    // --- Frequency counter update ---
    if (hit) {
        if (lstates[way].freq_counter < ((1 << FREQ_BITS) - 1))
            lstates[way].freq_counter++;
    } else {
        // On miss/insertion: check for spatial stride match
        bool spatial_boost = false;
        if (!sstate.stride_history.empty()) {
            int64_t curr_stride = sstate.stride_history.back();
            int match = 0;
            for (auto s : sstate.stride_history)
                if (s == curr_stride) match++;
            if (match >= SPATIAL_MATCH) spatial_boost = true;
        }
        lstates[way].spatial_boosted = spatial_boost;
        if (spatial_boost) {
            lstates[way].freq_counter = ((1 << FREQ_BITS) - 1) / 2; // Give a frequency boost
        } else {
            lstates[way].freq_counter = 0;
        }
    }

    // --- Save tag for stride detection (optional, can be used for more advanced matching) ---
    lstates[way].tag = paddr >> 6;
}

void PrintStats() {
    std::cout << "AMSR: Total evictions: " << total_evictions << std::endl;
    std::cout << "AMSR: Frequency-priority evictions: " << freq_evictions << std::endl;
    std::cout << "AMSR: LRU-priority evictions: " << lru_evictions << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "AMSR heartbeat: evictions=" << total_evictions
              << " freq_evictions=" << freq_evictions
              << " lru_evictions=" << lru_evictions << std::endl;
}