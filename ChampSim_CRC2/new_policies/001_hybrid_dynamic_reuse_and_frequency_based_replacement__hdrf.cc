#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Policy Parameters ---
constexpr int FREQ_MAX = 7;             // Max frequency counter value per line
constexpr int MISS_WINDOW = 128;        // Window for set-level miss/hit tracking
constexpr int MISS_THRESHOLD = 32;      // If misses in window exceed this, treat as irregular
constexpr int DECAY_INTERVAL = 1024;    // How often to decay frequency counters

struct LineState {
    uint8_t lru_position;   // 0 = MRU, LLC_WAYS-1 = LRU
    uint8_t freq_counter;   // Frequency counter (0..FREQ_MAX)
};

struct SetState {
    uint32_t window_hits;
    uint32_t window_misses;
    uint32_t last_decay_time;
    bool prefer_freq;       // If true, evict by frequency, else by LRU
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;
uint32_t global_time = 0;

// Telemetry
uint64_t total_evictions = 0;
uint64_t freq_evictions = 0;
uint64_t lru_evictions = 0;
std::array<uint64_t, LLC_SETS> set_freq_evictions = {};

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way] = {static_cast<uint8_t>(way), 0};
        }
        set_states[set] = {};
        set_states[set].window_hits = 0;
        set_states[set].window_misses = 0;
        set_states[set].last_decay_time = 0;
        set_states[set].prefer_freq = false;
    }
    global_time = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    global_time++;

    // --- Adaptive Filtering ---
    auto& sstate = set_states[set];
    // If recent miss rate high, prefer frequency-based eviction
    if ((sstate.window_misses + sstate.window_hits) >= MISS_WINDOW) {
        if (sstate.window_misses > MISS_THRESHOLD) {
            sstate.prefer_freq = true;
        } else {
            sstate.prefer_freq = false;
        }
        sstate.window_hits = 0;
        sstate.window_misses = 0;
    }

    int victim = -1;
    if (sstate.prefer_freq) {
        // Evict line with lowest frequency (break ties by LRU)
        uint8_t min_freq = FREQ_MAX+1;
        uint8_t max_lru = 0;
        for (int way = 0; way < LLC_WAYS; ++way) {
            uint8_t f = line_states[set][way].freq_counter;
            uint8_t lru = line_states[set][way].lru_position;
            if (f < min_freq || (f == min_freq && lru > max_lru)) {
                min_freq = f;
                max_lru = lru;
                victim = way;
            }
        }
        freq_evictions++;
        set_freq_evictions[set]++;
    } else {
        // Standard LRU eviction
        uint8_t max_lru = 0;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (line_states[set][way].lru_position > max_lru) {
                max_lru = line_states[set][way].lru_position;
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
    global_time++;
    auto& sstate = set_states[set];
    auto& lstates = line_states[set];

    // --- Window miss/hit tracking ---
    if (hit) sstate.window_hits++;
    else     sstate.window_misses++;

    // --- Frequency update ---
    if (hit) {
        lstates[way].freq_counter = std::min(FREQ_MAX, lstates[way].freq_counter + 1);
    } else {
        lstates[way].freq_counter = std::max(0, lstates[way].freq_counter - 1);
    }

    // --- LRU update ---
    uint8_t old_pos = lstates[way].lru_position;
    for (int w = 0; w < LLC_WAYS; ++w) {
        if (w == way) continue;
        if (lstates[w].lru_position < old_pos)
            lstates[w].lru_position++;
    }
    lstates[way].lru_position = 0;

    // --- Periodic frequency decay (to avoid stale frequency) ---
    if (global_time - sstate.last_decay_time > DECAY_INTERVAL) {
        for (int w = 0; w < LLC_WAYS; ++w) {
            lstates[w].freq_counter = std::max(0, lstates[w].freq_counter - 1);
        }
        sstate.last_decay_time = global_time;
    }
}

void PrintStats() {
    std::cout << "HDRF: Total evictions: " << total_evictions << std::endl;
    std::cout << "HDRF: Frequency-based evictions: " << freq_evictions << std::endl;
    std::cout << "HDRF: LRU-based evictions: " << lru_evictions << std::endl;
    std::cout << "HDRF: Sets using freq-based eviction (nonzero): ";
    int cnt = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set_freq_evictions[set] > 0) {
            std::cout << "[" << set << "]=" << set_freq_evictions[set] << " ";
            cnt++;
            if (cnt > 20) { std::cout << "..."; break; }
        }
    }
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "HDRF heartbeat: evictions=" << total_evictions
              << " freq_evictions=" << freq_evictions
              << " lru_evictions=" << lru_evictions << std::endl;
}