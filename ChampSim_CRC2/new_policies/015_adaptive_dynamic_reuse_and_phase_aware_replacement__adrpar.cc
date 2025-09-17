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
constexpr int PHASE_WINDOW = 16;
constexpr int STRIDE_HISTORY = 8;
constexpr int PC_HISTORY = 8;
constexpr int PHASE_REGULAR_THRESHOLD = 3;
constexpr int PHASE_IRREGULAR_THRESHOLD = 6;

struct LineState {
    uint64_t tag;
    uint8_t valid;
    uint8_t reuse_counter; // Temporal locality
    uint64_t last_pc;
};

struct SetState {
    std::vector<uint64_t> addr_history;
    std::vector<uint64_t> pc_history;
    int detected_stride;
    int phase_type; // 0: unknown, 1: regular, 2: irregular, 3: mixed
    std::unordered_map<uint64_t, int> pc_freq;
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t total_evictions = 0;
uint64_t regular_evictions = 0;
uint64_t irregular_evictions = 0;
uint64_t reuse_evictions = 0;
uint64_t lru_evictions = 0;

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

// Helper: Detect phase type (regular/irregular/mixed) based on address and PC entropy
int detect_phase(const std::vector<uint64_t>& addr_history, const std::vector<uint64_t>& pc_history) {
    // Regular: low unique PC count, stride detected
    // Irregular: high unique PC count, no stride
    // Mixed: in between
    std::unordered_map<uint64_t, int> pc_map;
    for (auto pc : pc_history) pc_map[pc]++;
    int unique_pc = pc_map.size();

    int stride = detect_stride(addr_history);
    if (stride != 0 && unique_pc <= PHASE_REGULAR_THRESHOLD)
        return 1; // regular
    else if (unique_pc >= PHASE_IRREGULAR_THRESHOLD)
        return 2; // irregular
    else
        return 3; // mixed
}

// Initialize replacement state
void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].valid = 0;
            line_states[set][way].reuse_counter = REUSE_MAX;
            line_states[set][way].last_pc = 0;
        }
        set_states[set].addr_history.clear();
        set_states[set].pc_history.clear();
        set_states[set].detected_stride = 0;
        set_states[set].phase_type = 0;
        set_states[set].pc_freq.clear();
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

    // 1. Prefer invalid block
    for (int way = 0; way < LLC_WAYS; ++way)
        if (!lstates[way].valid)
            return way;

    // 2. Use phase-aware victim selection
    // Regular phase: evict block with highest reuse_counter (least recently used)
    // Irregular phase: evict block with lowest PC frequency (least pointer-chased)
    // Mixed: combine both (average rank)
    int victim = -1;
    if (sstate.phase_type == 1) { // regular
        int max_reuse = -1;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (lstates[way].reuse_counter > max_reuse) {
                max_reuse = lstates[way].reuse_counter;
                victim = way;
            }
        }
        regular_evictions++;
    } else if (sstate.phase_type == 2) { // irregular
        int min_pc_freq = 100000;
        for (int way = 0; way < LLC_WAYS; ++way) {
            uint64_t pc_hash = lstates[way].last_pc & 0xFFF;
            int freq = sstate.pc_freq.count(pc_hash) ? sstate.pc_freq[pc_hash] : 0;
            if (freq < min_pc_freq) {
                min_pc_freq = freq;
                victim = way;
            }
        }
        irregular_evictions++;
    } else { // mixed or unknown
        // Weighted rank: reuse_counter + (max_freq - pc_freq)
        int best_score = -100000, best_way = -1;
        int max_freq = 0;
        for (auto& kv : sstate.pc_freq)
            if (kv.second > max_freq) max_freq = kv.second;
        for (int way = 0; way < LLC_WAYS; ++way) {
            uint64_t pc_hash = lstates[way].last_pc & 0xFFF;
            int freq = sstate.pc_freq.count(pc_hash) ? sstate.pc_freq[pc_hash] : 0;
            int score = -(int)lstates[way].reuse_counter + (max_freq - freq);
            if (score > best_score) {
                best_score = score;
                best_way = way;
            }
        }
        victim = best_way;
        reuse_evictions++;
    }
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

    // --- Address/PC history for phase detection ---
    if (sstate.addr_history.size() >= STRIDE_HISTORY)
        sstate.addr_history.erase(sstate.addr_history.begin());
    sstate.addr_history.push_back(paddr);

    if (sstate.pc_history.size() >= PC_HISTORY)
        sstate.pc_history.erase(sstate.pc_history.begin());
    sstate.pc_history.push_back(PC);

    // --- PC frequency tracking for pointer-chasing detection ---
    uint64_t pc_hash = PC & 0xFFF;
    sstate.pc_freq[pc_hash]++;
    if (sstate.pc_freq.size() > 32) {
        // Remove least used
        uint64_t min_pc = 0; int min_count = 100000;
        for (auto& kv : sstate.pc_freq)
            if (kv.second < min_count) { min_pc = kv.first; min_count = kv.second; }
        sstate.pc_freq.erase(min_pc);
    }

    // --- Phase detection ---
    sstate.phase_type = detect_phase(sstate.addr_history, sstate.pc_history);
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ADRPAR: Total evictions: " << total_evictions << std::endl;
    std::cout << "ADRPAR: Regular phase evictions: " << regular_evictions << std::endl;
    std::cout << "ADRPAR: Irregular phase evictions: " << irregular_evictions << std::endl;
    std::cout << "ADRPAR: Mixed/reuse-based evictions: " << reuse_evictions << std::endl;
    std::cout << "ADRPAR: LRU evictions: " << lru_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "ADRPAR heartbeat: evictions=" << total_evictions
              << " regular=" << regular_evictions
              << " irregular=" << irregular_evictions
              << " reuse=" << reuse_evictions
              << " lru=" << lru_evictions << std::endl;
}