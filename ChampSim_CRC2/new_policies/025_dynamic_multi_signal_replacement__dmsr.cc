#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr uint32_t FREQ_MAX = 255;
constexpr uint32_t RDIST_MAX = 15;
constexpr uint32_t RDIST_MIN = 0;
constexpr uint32_t PHASE_WINDOW = 32;
constexpr uint32_t STRIDE_HISTORY = 8;

struct LineState {
    uint64_t tag;
    uint8_t valid;
    uint32_t freq;           // Access frequency
    uint32_t last_access;    // Timestamp for LRU
    uint8_t rdist;           // Estimated reuse distance (saturating counter)
    int64_t last_addr;       // Last physical address
    int64_t stride;          // Last observed stride
};

struct SetState {
    uint32_t timestamp;
    uint32_t recent_hits;
    uint32_t recent_misses;
    uint8_t phase_ptr;
    uint8_t phase_history[PHASE_WINDOW];
    int64_t stride_hist[STRIDE_HISTORY];
    uint8_t stride_ptr;
    bool spatial_phase;      // True if stride regularity detected
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t lru_evictions = 0;
uint64_t freq_evictions = 0;
uint64_t rdist_evictions = 0;
uint64_t hybrid_evictions = 0;
uint64_t total_evictions = 0;

// Helper: Detect phase change (low hit rate)
bool phase_change(const SetState& sstate) {
    int sum = 0;
    for (int i = 0; i < PHASE_WINDOW; ++i)
        sum += sstate.phase_history[i];
    return sum < PHASE_WINDOW / 4; // <25% hits in window
}

// Helper: Detect stride regularity (spatial phase)
bool detect_spatial_phase(const SetState& sstate) {
    std::vector<int64_t> strides;
    for (int i = 0; i < STRIDE_HISTORY; ++i)
        if (sstate.stride_hist[i] != 0)
            strides.push_back(sstate.stride_hist[i]);
    if (strides.size() < 4) return false;
    std::sort(strides.begin(), strides.end());
    int64_t candidate = strides[strides.size()/2];
    int count = std::count(strides.begin(), strides.end(), candidate);
    return count >= (int)strides.size()/2;
}

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].valid = 0;
            line_states[set][way].freq = 0;
            line_states[set][way].last_access = 0;
            line_states[set][way].rdist = 0;
            line_states[set][way].last_addr = -1;
            line_states[set][way].stride = 0;
        }
        set_states[set].timestamp = 0;
        set_states[set].recent_hits = 0;
        set_states[set].recent_misses = 0;
        set_states[set].phase_ptr = 0;
        std::memset(set_states[set].phase_history, 0, sizeof(set_states[set].phase_history));
        std::memset(set_states[set].stride_hist, 0, sizeof(set_states[set].stride_hist));
        set_states[set].stride_ptr = 0;
        set_states[set].spatial_phase = false;
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
    auto& sstate = set_states[set];

    // Step 1: Prefer invalid way
    for (int way = 0; way < LLC_WAYS; ++way)
        if (!lstates[way].valid)
            return way;

    // Step 2: Update spatial phase detection
    sstate.spatial_phase = detect_spatial_phase(sstate);

    // Step 3: If phase change detected (low hit rate), fallback to LRU
    if (phase_change(sstate)) {
        uint32_t oldest = UINT32_MAX;
        int victim = -1;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (lstates[way].last_access < oldest) {
                oldest = lstates[way].last_access;
                victim = way;
            }
        }
        lru_evictions++; total_evictions++;
        return victim;
    }

    // Step 4: If spatial phase (stride regularity), evict block with highest rdist (least likely to be reused soon)
    if (sstate.spatial_phase) {
        int victim = -1;
        uint8_t max_rdist = RDIST_MIN - 1;
        uint32_t oldest = UINT32_MAX;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (lstates[way].rdist > max_rdist ||
                (lstates[way].rdist == max_rdist && lstates[way].last_access < oldest)) {
                max_rdist = lstates[way].rdist;
                oldest = lstates[way].last_access;
                victim = way;
            }
        }
        rdist_evictions++; total_evictions++;
        return victim;
    }

    // Step 5: If not spatial, evict block with lowest frequency, breaking ties with LRU
    int victim = -1;
    uint32_t min_freq = FREQ_MAX + 1;
    uint32_t oldest = UINT32_MAX;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].freq < min_freq ||
            (lstates[way].freq == min_freq && lstates[way].last_access < oldest)) {
            min_freq = lstates[way].freq;
            oldest = lstates[way].last_access;
            victim = way;
        }
    }
    freq_evictions++; total_evictions++;
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

    // --- Update reuse distance estimate ---
    // If hit, block reused soon; decrease rdist. If miss, increase (saturating).
    if (hit) {
        if (lstates[way].rdist > RDIST_MIN)
            lstates[way].rdist--;
    } else {
        if (lstates[way].rdist < RDIST_MAX)
            lstates[way].rdist++;
    }

    // --- Update frequency count ---
    if (hit) {
        if (lstates[way].freq < FREQ_MAX)
            lstates[way].freq++;
    } else {
        // On miss, decay frequency to avoid stale blocks
        if (lstates[way].freq > 0)
            lstates[way].freq--;
    }

    lstates[way].tag = paddr;
    lstates[way].valid = 1;
}

void PrintStats() {
    std::cout << "DMSR: Total evictions: " << total_evictions << std::endl;
    std::cout << "DMSR: LRU evictions: " << lru_evictions << std::endl;
    std::cout << "DMSR: Frequency evictions: " << freq_evictions << std::endl;
    std::cout << "DMSR: Reuse distance evictions: " << rdist_evictions << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "DMSR heartbeat: evictions=" << total_evictions
              << " lru_evictions=" << lru_evictions
              << " freq_evictions=" << freq_evictions
              << " rdist_evictions=" << rdist_evictions << std::endl;
}