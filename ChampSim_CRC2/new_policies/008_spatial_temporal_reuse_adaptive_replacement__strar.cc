#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int REUSE_HISTORY = 16;     // Per-set reuse history length
constexpr int STRIDE_WINDOW = 8;      // Window for stride detection
constexpr int STRIDE_CONFIDENCE = 6;  // If stride repeats > threshold, consider regular
constexpr int SWITCH_THRESHOLD = 10;  // If miss rate > threshold, switch mode

enum SetMode { SPATIAL, TEMPORAL };

// Per-line state
struct LineState {
    uint64_t tag;
    uint64_t last_paddr;
    uint64_t last_PC;
    int reuse_counter; // For temporal prediction
    int stride_match;  // For spatial prediction
};

// Per-set state
struct SetState {
    SetMode mode;
    std::vector<uint64_t> recent_addrs; // For stride detection
    std::vector<uint64_t> recent_pcs;   // For temporal reuse
    int stride_count;
    int miss_count;
    int hit_count;
    uint64_t last_stride;
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t spatial_evictions = 0;
uint64_t temporal_evictions = 0;
uint64_t total_evictions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].last_paddr = 0;
            line_states[set][way].last_PC = 0;
            line_states[set][way].reuse_counter = 0;
            line_states[set][way].stride_match = 0;
        }
        set_states[set].mode = SPATIAL;
        set_states[set].recent_addrs.assign(STRIDE_WINDOW, 0);
        set_states[set].recent_pcs.assign(REUSE_HISTORY, 0);
        set_states[set].stride_count = 0;
        set_states[set].miss_count = 0;
        set_states[set].hit_count = 0;
        set_states[set].last_stride = 0;
    }
}

// Find victim in the set
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

    if (sstate.mode == SPATIAL) {
        // Evict block with lowest stride_match (least spatial reuse)
        int min_match = lstates[0].stride_match;
        int victim = 0;
        for (int way = 1; way < LLC_WAYS; ++way) {
            if (lstates[way].stride_match < min_match) {
                min_match = lstates[way].stride_match;
                victim = way;
            }
        }
        spatial_evictions++;
        total_evictions++;
        return victim;
    } else {
        // Evict block with lowest reuse_counter (least temporal reuse)
        int min_reuse = lstates[0].reuse_counter;
        int victim = 0;
        for (int way = 1; way < LLC_WAYS; ++way) {
            if (lstates[way].reuse_counter < min_reuse) {
                min_reuse = lstates[way].reuse_counter;
                victim = way;
            }
        }
        temporal_evictions++;
        total_evictions++;
        return victim;
    }
}

// Update replacement state
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

    // --- Update miss/hit counters ---
    if (hit) sstate.hit_count++;
    else sstate.miss_count++;

    // --- Update spatial stride detection ---
    uint64_t prev_addr = sstate.recent_addrs.back();
    uint64_t stride = (prev_addr != 0) ? (paddr - prev_addr) : 0;
    sstate.recent_addrs.erase(sstate.recent_addrs.begin());
    sstate.recent_addrs.push_back(paddr);

    if (stride != 0 && stride == sstate.last_stride)
        sstate.stride_count++;
    else
        sstate.stride_count = std::max(0, sstate.stride_count - 1);

    sstate.last_stride = stride;

    // --- Update per-line spatial reuse ---
    if (stride != 0 && stride == lstates.last_paddr - paddr)
        lstates.stride_match++;
    else
        lstates.stride_match = std::max(0, lstates.stride_match - 1);

    lstates.last_paddr = paddr;

    // --- Update temporal reuse predictor ---
    // If PC seen recently, boost reuse_counter
    if (std::find(sstate.recent_pcs.begin(), sstate.recent_pcs.end(), PC) != sstate.recent_pcs.end())
        lstates.reuse_counter = std::min(15, lstates.reuse_counter + 2);
    else
        lstates.reuse_counter = std::max(0, lstates.reuse_counter - 1);

    // Update PC history
    sstate.recent_pcs.erase(sstate.recent_pcs.begin());
    sstate.recent_pcs.push_back(PC);

    // --- Adapt mode based on stride regularity and miss rate ---
    // If stride_count is high, use SPATIAL; if miss rate is high or stride_count is low, use TEMPORAL
    int total_access = sstate.hit_count + sstate.miss_count;
    int miss_rate = (total_access > 0) ? (100 * sstate.miss_count / total_access) : 0;

    if (sstate.stride_count >= STRIDE_CONFIDENCE && miss_rate < SWITCH_THRESHOLD)
        sstate.mode = SPATIAL;
    else
        sstate.mode = TEMPORAL;

    // Reset counters periodically to adapt to phase changes
    if (total_access > 128) {
        sstate.stride_count = 0;
        sstate.hit_count = 0;
        sstate.miss_count = 0;
    }

    // Update line tag and PC
    lstates.tag = paddr;
    lstates.last_PC = PC;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "STRAR: Total evictions: " << total_evictions << std::endl;
    std::cout << "STRAR: Spatial evictions: " << spatial_evictions << std::endl;
    std::cout << "STRAR: Temporal evictions: " << temporal_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "STRAR heartbeat: evictions=" << total_evictions
              << " spatial=" << spatial_evictions
              << " temporal=" << temporal_evictions << std::endl;
}