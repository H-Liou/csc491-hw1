#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int REUSE_MAX = 255;
constexpr int STRIDE_HISTORY = 8;
constexpr int PC_FREQ_SIZE = 32;
constexpr int SPATIAL_WINDOW = 4; // For spatial locality scoring

struct LineState {
    uint64_t tag;
    uint8_t valid;
    uint8_t reuse_counter; // Temporal locality
    uint64_t last_pc;
    int spatial_score; // How close to recent stride
};

struct SetState {
    std::vector<uint64_t> addr_history;
    int detected_stride;
    std::unordered_map<uint64_t, int> pc_freq;
    uint64_t last_addr;
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t total_evictions = 0;
uint64_t spatial_evictions = 0;
uint64_t pc_evictions = 0;
uint64_t reuse_evictions = 0;

// Helper: Detect stride in address history
int detect_stride(const std::vector<uint64_t>& history) {
    if (history.size() < 3) return 0;
    int64_t stride = history[1] - history[0];
    for (size_t i = 2; i < history.size(); ++i) {
        if ((int64_t)(history[i] - history[i-1]) != stride)
            return 0;
    }
    return (int)stride;
}

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].valid = 0;
            line_states[set][way].reuse_counter = REUSE_MAX;
            line_states[set][way].last_pc = 0;
            line_states[set][way].spatial_score = 0;
        }
        set_states[set].addr_history.clear();
        set_states[set].detected_stride = 0;
        set_states[set].pc_freq.clear();
        set_states[set].last_addr = 0;
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
    auto& lstates = line_states[set];
    auto& sstate = set_states[set];

    // Prefer invalid block
    for (int way = 0; way < LLC_WAYS; ++way)
        if (!lstates[way].valid)
            return way;

    // Use hybrid scoring:
    // Score = w1*reuse_counter + w2*spatial_score + w3*(max_pc_freq - pc_freq)
    // Weights adapt based on stride detection and PC frequency diversity

    // Calculate weights
    int stride = sstate.detected_stride;
    int unique_pc = sstate.pc_freq.size();
    int w_reuse = 2, w_spatial = 2, w_pc = 2;
    if (stride != 0 && unique_pc < 8) {
        // Regular/stride phase
        w_spatial = 4; w_reuse = 3; w_pc = 1;
    } else if (unique_pc > 16) {
        // Irregular/pointer-chasing phase
        w_spatial = 1; w_reuse = 2; w_pc = 4;
    } else {
        // Mixed
        w_spatial = 2; w_reuse = 2; w_pc = 2;
    }

    // Find max PC frequency for normalization
    int max_pc_freq = 1;
    for (auto& kv : sstate.pc_freq) if (kv.second > max_pc_freq) max_pc_freq = kv.second;

    int best_score = -100000, victim = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        int reuse = lstates[way].reuse_counter;
        int spatial = lstates[way].spatial_score;
        uint64_t pc_hash = lstates[way].last_pc & 0xFFF;
        int pc_freq = sstate.pc_freq.count(pc_hash) ? sstate.pc_freq[pc_hash] : 0;
        int score = w_reuse*reuse + w_spatial*spatial + w_pc*(max_pc_freq - pc_freq);
        // Lower score = better victim
        if (score > best_score) {
            best_score = score;
            victim = way;
        }
    }

    // Stats
    if (w_spatial > w_pc && w_spatial > w_reuse) spatial_evictions++;
    else if (w_pc > w_spatial && w_pc > w_reuse) pc_evictions++;
    else reuse_evictions++;
    total_evictions++;

    return victim;
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
    auto& lstates = line_states[set];
    auto& sstate = set_states[set];

    // Update per-line state
    lstates[way].tag = paddr;
    lstates[way].valid = 1;
    lstates[way].last_pc = PC;

    // --- Reuse interval tracking ---
    for (int i = 0; i < LLC_WAYS; ++i)
        if (lstates[i].reuse_counter < REUSE_MAX)
            lstates[i].reuse_counter++;
    lstates[way].reuse_counter = 0;

    // --- Address history for stride detection ---
    if (sstate.addr_history.size() >= STRIDE_HISTORY)
        sstate.addr_history.erase(sstate.addr_history.begin());
    sstate.addr_history.push_back(paddr);

    sstate.detected_stride = detect_stride(sstate.addr_history);

    // --- PC frequency tracking ---
    uint64_t pc_hash = PC & 0xFFF;
    sstate.pc_freq[pc_hash]++;
    if (sstate.pc_freq.size() > PC_FREQ_SIZE) {
        // Remove least used
        uint64_t min_pc = 0; int min_count = 100000;
        for (auto& kv : sstate.pc_freq)
            if (kv.second < min_count) { min_pc = kv.first; min_count = kv.second; }
        sstate.pc_freq.erase(min_pc);
    }

    // --- Spatial locality scoring ---
    int spatial_score = 0;
    if (sstate.detected_stride != 0) {
        int64_t dist = (int64_t)paddr - (int64_t)sstate.last_addr;
        if (dist == sstate.detected_stride)
            spatial_score = 0; // perfect stride
        else if (std::abs(dist) <= SPATIAL_WINDOW * std::abs(sstate.detected_stride))
            spatial_score = 1;
        else
            spatial_score = 2;
    } else {
        spatial_score = 2; // unknown stride, less spatial
    }
    lstates[way].spatial_score = spatial_score;
    sstate.last_addr = paddr;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "HLPCFR: Total evictions: " << total_evictions << std::endl;
    std::cout << "HLPCFR: Spatial evictions: " << spatial_evictions << std::endl;
    std::cout << "HLPCFR: PC-based evictions: " << pc_evictions << std::endl;
    std::cout << "HLPCFR: Reuse-based evictions: " << reuse_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "HLPCFR heartbeat: evictions=" << total_evictions
              << " spatial=" << spatial_evictions
              << " pc=" << pc_evictions
              << " reuse=" << reuse_evictions << std::endl;
}