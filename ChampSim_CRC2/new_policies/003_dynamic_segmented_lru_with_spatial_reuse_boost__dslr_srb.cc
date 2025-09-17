#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <array>
#include <deque>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Policy Parameters ---
constexpr int PROTECTED_MIN = 4;      // Minimum protected segment size
constexpr int PROTECTED_MAX = 12;     // Maximum protected segment size
constexpr int SEGMENT_WINDOW = 128;   // Window for set-level miss/hit tracking
constexpr int SEGMENT_MISS_HIGH = 32; // If misses in window exceed this, shrink protected
constexpr int SEGMENT_MISS_LOW = 8;   // If misses are low, grow protected
constexpr int SPATIAL_HISTORY = 8;    // Number of recent strides to track
constexpr int SPATIAL_BOOST = 2;      // Number of ways to boost for spatial locality

struct LineState {
    uint8_t lru_position;    // 0 = MRU, LLC_WAYS-1 = LRU
    bool protected_line;     // Is this line in the protected segment?
    bool spatial_boosted;    // Is this line spatially boosted?
    uint64_t tag;            // For stride detection
};

struct SetState {
    uint32_t window_hits;
    uint32_t window_misses;
    int protected_size;      // Current protected segment size
    std::deque<int64_t> stride_history; // Recent access strides
    uint64_t last_addr;      // Last address accessed in this set
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Telemetry
uint64_t total_evictions = 0;
uint64_t protected_evictions = 0;
uint64_t probation_evictions = 0;
std::array<uint64_t, LLC_SETS> set_protected_evictions = {};
std::array<uint64_t, LLC_SETS> set_probation_evictions = {};

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way] = {static_cast<uint8_t>(way), false, false, 0};
        }
        set_states[set] = {};
        set_states[set].window_hits = 0;
        set_states[set].window_misses = 0;
        set_states[set].protected_size = (PROTECTED_MIN + PROTECTED_MAX) / 2;
        set_states[set].stride_history.clear();
        set_states[set].last_addr = 0;
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

    // --- Segment boundary adjustment ---
    if ((sstate.window_hits + sstate.window_misses) >= SEGMENT_WINDOW) {
        if (sstate.window_misses > SEGMENT_MISS_HIGH) {
            sstate.protected_size = std::max(PROTECTED_MIN, sstate.protected_size - 1);
        } else if (sstate.window_misses < SEGMENT_MISS_LOW) {
            sstate.protected_size = std::min(PROTECTED_MAX, sstate.protected_size + 1);
        }
        sstate.window_hits = 0;
        sstate.window_misses = 0;
    }

    // --- Victim selection ---
    // Prefer to evict from probation segment (not protected)
    int victim = -1;
    uint8_t max_lru = 0;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (!lstates[way].protected_line && !lstates[way].spatial_boosted) {
            if (lstates[way].lru_position > max_lru) {
                max_lru = lstates[way].lru_position;
                victim = way;
            }
        }
    }
    if (victim >= 0) {
        probation_evictions++;
        set_probation_evictions[set]++;
    } else {
        // All lines are protected or spatially boosted, evict from protected segment
        max_lru = 0;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (lstates[way].lru_position > max_lru) {
                max_lru = lstates[way].lru_position;
                victim = way;
            }
        }
        protected_evictions++;
        set_protected_evictions[set]++;
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

    // --- Window miss/hit tracking ---
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

    // --- Protected segment management ---
    // On hit: promote to protected if not already, demote oldest protected if over size
    if (hit) {
        lstates[way].protected_line = true;
        // Count protected lines
        int prot_count = 0;
        for (int w = 0; w < LLC_WAYS; ++w)
            if (lstates[w].protected_line) prot_count++;
        if (prot_count > sstate.protected_size) {
            // Demote oldest protected line (highest LRU)
            int oldest = -1;
            uint8_t max_lru = 0;
            for (int w = 0; w < LLC_WAYS; ++w) {
                if (lstates[w].protected_line && lstates[w].lru_position > max_lru) {
                    max_lru = lstates[w].lru_position;
                    oldest = w;
                }
            }
            if (oldest >= 0)
                lstates[oldest].protected_line = false;
        }
    } else {
        // On miss: new line, decide if spatially boosted
        // If stride matches recent history (e.g., regular stride), spatially boost
        bool spatial_boost = false;
        if (!sstate.stride_history.empty()) {
            int64_t curr_stride = sstate.stride_history.back();
            int match = 0;
            for (auto s : sstate.stride_history)
                if (s == curr_stride) match++;
            if (match >= (SPATIAL_HISTORY / 2)) spatial_boost = true;
        }
        lstates[way].spatial_boosted = spatial_boost;
        lstates[way].protected_line = spatial_boost;
        // Limit number of spatially boosted lines
        int boost_count = 0;
        for (int w = 0; w < LLC_WAYS; ++w)
            if (lstates[w].spatial_boosted) boost_count++;
        if (boost_count > SPATIAL_BOOST) {
            // Demote oldest boosted line
            int oldest = -1;
            uint8_t max_lru = 0;
            for (int w = 0; w < LLC_WAYS; ++w) {
                if (lstates[w].spatial_boosted && lstates[w].lru_position > max_lru) {
                    max_lru = lstates[w].lru_position;
                    oldest = w;
                }
            }
            if (oldest >= 0)
                lstates[oldest].spatial_boosted = false;
        }
    }

    // --- Save tag for stride detection (optional, can be used for more advanced matching) ---
    lstates[way].tag = paddr >> 6;
}

void PrintStats() {
    std::cout << "DSLR-SRB: Total evictions: " << total_evictions << std::endl;
    std::cout << "DSLR-SRB: Protected segment evictions: " << protected_evictions << std::endl;
    std::cout << "DSLR-SRB: Probation segment evictions: " << probation_evictions << std::endl;
    std::cout << "DSLR-SRB: Sets with protected evictions: ";
    int cnt = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set_protected_evictions[set] > 0) {
            std::cout << "[" << set << "]=" << set_protected_evictions[set] << " ";
            cnt++;
            if (cnt > 20) { std::cout << "..."; break; }
        }
    }
    std::cout << std::endl;
    std::cout << "DSLR-SRB: Sets with probation evictions: ";
    cnt = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set_probation_evictions[set] > 0) {
            std::cout << "[" << set << "]=" << set_probation_evictions[set] << " ";
            cnt++;
            if (cnt > 20) { std::cout << "..."; break; }
        }
    }
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "DSLR-SRB heartbeat: evictions=" << total_evictions
              << " protected_evictions=" << protected_evictions
              << " probation_evictions=" << probation_evictions << std::endl;
}