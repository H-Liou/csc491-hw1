#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr uint32_t REUSE_MAX = 1023;
constexpr uint32_t REUSE_MIN = 0;
constexpr uint32_t STRIDE_HISTORY = 8;
constexpr uint32_t PHASE_WINDOW = 32;
constexpr uint32_t SPATIAL_SCORE_MAX = 15;
constexpr uint32_t SPATIAL_SCORE_MIN = 0;

struct LineState {
    uint64_t tag;
    uint8_t valid;
    uint32_t last_access;     // Timestamp of last access
    uint32_t reuse_interval;  // Predicted reuse distance (in accesses)
    int64_t last_addr;        // Last physical address accessed
    int64_t stride;           // Detected stride
    uint8_t spatial_score;    // Score for spatial correlation
};

struct SetState {
    uint32_t timestamp; // Global set timestamp
    uint32_t recent_hits;
    uint32_t recent_misses;
    uint8_t phase_ptr;
    uint8_t phase_history[PHASE_WINDOW];
    int64_t stride_hist[STRIDE_HISTORY];
    uint8_t stride_ptr;
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t total_evictions = 0;
uint64_t spatial_evictions = 0;
uint64_t reuse_evictions = 0;
uint64_t lru_evictions = 0;
uint64_t spatial_promotions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].valid = 0;
            line_states[set][way].last_access = 0;
            line_states[set][way].reuse_interval = REUSE_MAX / 2;
            line_states[set][way].last_addr = -1;
            line_states[set][way].stride = 0;
            line_states[set][way].spatial_score = 0;
        }
        set_states[set].timestamp = 0;
        set_states[set].recent_hits = 0;
        set_states[set].recent_misses = 0;
        set_states[set].phase_ptr = 0;
        std::memset(set_states[set].phase_history, 0, sizeof(set_states[set].phase_history));
        std::memset(set_states[set].stride_hist, 0, sizeof(set_states[set].stride_hist));
        set_states[set].stride_ptr = 0;
    }
}

// Helper: Detect phase change (drop in hit rate)
bool phase_change(const SetState& sstate) {
    int sum = 0;
    for (int i = 0; i < PHASE_WINDOW; ++i)
        sum += sstate.phase_history[i];
    return sum < PHASE_WINDOW / 4; // <25% hits in window
}

// Helper: Detect dominant stride in recent accesses
int64_t detect_stride(const SetState& sstate) {
    // Majority stride in history
    std::vector<int64_t> strides;
    for (int i = 0; i < STRIDE_HISTORY; ++i)
        if (sstate.stride_hist[i] != 0)
            strides.push_back(sstate.stride_hist[i]);
    if (strides.empty()) return 0;
    std::sort(strides.begin(), strides.end());
    int64_t candidate = strides[strides.size()/2];
    // Check if candidate is dominant
    int count = std::count(strides.begin(), strides.end(), candidate);
    if (count >= (int)strides.size()/2)
        return candidate;
    return 0;
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
    auto& sstate = set_states[set];

    // Step 1: Prefer invalid way
    for (int way = 0; way < LLC_WAYS; ++way)
        if (!lstates[way].valid)
            return way;

    // Step 2: If phase change detected, evict block with longest predicted reuse interval
    if (phase_change(sstate)) {
        uint32_t victim = 0;
        uint32_t max_reuse = REUSE_MIN - 1;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (lstates[way].reuse_interval > max_reuse) {
                max_reuse = lstates[way].reuse_interval;
                victim = way;
            }
        }
        reuse_evictions++;
        total_evictions++;
        return victim;
    }

    // Step 3: Evict block with lowest spatial correlation (score), oldest access
    int victim = -1;
    uint8_t min_score = SPATIAL_SCORE_MAX + 1;
    uint32_t oldest = 0;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].spatial_score < min_score ||
            (lstates[way].spatial_score == min_score && lstates[way].last_access < oldest)) {
            min_score = lstates[way].spatial_score;
            oldest = lstates[way].last_access;
            victim = way;
        }
    }
    if (victim != -1) {
        spatial_evictions++;
        total_evictions++;
        return victim;
    }

    // Step 4: Fallback to LRU (oldest last_access)
    oldest = UINT32_MAX;
    victim = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].last_access < oldest) {
            oldest = lstates[way].last_access;
            victim = way;
        }
    }
    lru_evictions++;
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
    auto& lstates = line_states[set];
    auto& sstate = set_states[set];

    // --- Update timestamp ---
    sstate.timestamp++;
    lstates[way].last_access = sstate.timestamp;

    // --- Update phase history ---
    if (hit) {
        sstate.recent_hits++;
        sstate.phase_history[sstate.phase_ptr] = 1;
    } else {
        sstate.recent_misses++;
        sstate.phase_history[sstate.phase_ptr] = 0;
    }
    sstate.phase_ptr = (sstate.phase_ptr + 1) % PHASE_WINDOW;

    // --- Update stride history for spatial detection ---
    int64_t stride = 0;
    if (lstates[way].last_addr != -1)
        stride = (int64_t)paddr - lstates[way].last_addr;
    sstate.stride_hist[sstate.stride_ptr] = stride;
    sstate.stride_ptr = (sstate.stride_ptr + 1) % STRIDE_HISTORY;
    lstates[way].last_addr = paddr;
    lstates[way].stride = stride;

    // --- Update spatial correlation score ---
    int64_t dominant_stride = detect_stride(sstate);
    if (dominant_stride != 0 && stride == dominant_stride) {
        if (lstates[way].spatial_score < SPATIAL_SCORE_MAX)
            lstates[way].spatial_score++;
        spatial_promotions++;
    } else {
        if (lstates[way].spatial_score > SPATIAL_SCORE_MIN)
            lstates[way].spatial_score--;
    }

    // --- Update reuse interval prediction ---
    if (hit) {
        uint32_t interval = sstate.timestamp - lstates[way].last_access;
        lstates[way].reuse_interval = (lstates[way].reuse_interval + interval) / 2;
    } else {
        lstates[way].reuse_interval = (lstates[way].reuse_interval + REUSE_MAX) / 2;
    }

    lstates[way].tag = paddr;
    lstates[way].valid = 1;
}

void PrintStats() {
    std::cout << "DRISCR: Total evictions: " << total_evictions << std::endl;
    std::cout << "DRISCR: Spatial evictions: " << spatial_evictions << std::endl;
    std::cout << "DRISCR: Reuse evictions: " << reuse_evictions << std::endl;
    std::cout << "DRISCR: LRU evictions: " << lru_evictions << std::endl;
    std::cout << "DRISCR: Spatial promotions: " << spatial_promotions << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "DRISCR heartbeat: evictions=" << total_evictions
              << " spatial_evictions=" << spatial_evictions
              << " reuse_evictions=" << reuse_evictions
              << " lru_evictions=" << lru_evictions
              << " spatial_promotions=" << spatial_promotions << std::endl;
}