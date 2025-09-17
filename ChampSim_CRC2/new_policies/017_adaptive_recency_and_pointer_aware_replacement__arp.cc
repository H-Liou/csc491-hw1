#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int LRU_MAX = LLC_WAYS - 1;
constexpr int STRIDE_HISTORY = 8;
constexpr int POINTER_PC_WINDOW = 16;
constexpr int POINTER_PC_THRESHOLD = 8;

// Per-line state: LRU stack, last PC, pointer-chasing mark
struct LineState {
    uint64_t tag;
    uint8_t valid;
    uint8_t lru_position;
    uint64_t last_pc;
    bool pointer_pc;
};

// Per-set state: address history for stride, pointer PC frequency
struct SetState {
    std::vector<uint64_t> addr_history;
    int detected_stride;
    std::unordered_map<uint64_t, int> pointer_pc_freq;
    int pointer_intensity; // # of pointer PCs in window
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t total_evictions = 0;
uint64_t lru_evictions = 0;
uint64_t pointer_evictions = 0;

// Simple stride detector
int detect_stride(const std::vector<uint64_t>& history) {
    if (history.size() < 3) return 0;
    int64_t stride = history[1] - history[0];
    for (size_t i = 2; i < history.size(); ++i) {
        if ((int64_t)(history[i] - history[i-1]) != stride)
            return 0;
    }
    return (int)stride;
}

// Identify pointer-chasing PC: heuristic (low spatial locality, frequent dereference)
// For simplicity, mark PCs with high frequency in set as pointer PCs
bool is_pointer_pc(uint64_t PC, SetState& sstate) {
    uint64_t pc_hash = PC & 0xFFF;
    return sstate.pointer_pc_freq[pc_hash] >= 2;
}

// Initialize replacement state
void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].valid = 0;
            line_states[set][way].lru_position = way;
            line_states[set][way].last_pc = 0;
            line_states[set][way].pointer_pc = false;
        }
        set_states[set].addr_history.clear();
        set_states[set].detected_stride = 0;
        set_states[set].pointer_pc_freq.clear();
        set_states[set].pointer_intensity = 0;
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

    // Detect phase: stride regularity and pointer intensity
    bool stride_phase = (sstate.detected_stride != 0);
    bool pointer_phase = (sstate.pointer_intensity >= POINTER_PC_THRESHOLD);

    // If stride phase and not pointer phase: use LRU
    if (stride_phase && !pointer_phase) {
        // LRU victim
        int lru_way = 0, max_lru = -1;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (lstates[way].lru_position > max_lru) {
                max_lru = lstates[way].lru_position;
                lru_way = way;
            }
        }
        lru_evictions++;
        total_evictions++;
        return lru_way;
    }

    // If pointer phase: evict non-pointer lines with highest LRU
    if (pointer_phase) {
        int victim = -1, max_lru = -1;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (!lstates[way].pointer_pc && lstates[way].lru_position > max_lru) {
                max_lru = lstates[way].lru_position;
                victim = way;
            }
        }
        if (victim != -1) {
            pointer_evictions++;
            total_evictions++;
            return victim;
        }
        // If all lines are pointer PCs, fallback to LRU
    }

    // Mixed phase or fallback: evict highest LRU
    int lru_way = 0, max_lru = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].lru_position > max_lru) {
            max_lru = lstates[way].lru_position;
            lru_way = way;
        }
    }
    lru_evictions++;
    total_evictions++;
    return lru_way;
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

    // --- LRU stack update ---
    uint8_t old_pos = lstates[way].lru_position;
    for (int i = 0; i < LLC_WAYS; ++i) {
        if (lstates[i].lru_position < old_pos)
            lstates[i].lru_position++;
    }
    lstates[way].lru_position = 0;

    // --- Address history for stride detection ---
    if (sstate.addr_history.size() >= STRIDE_HISTORY)
        sstate.addr_history.erase(sstate.addr_history.begin());
    sstate.addr_history.push_back(paddr);
    sstate.detected_stride = detect_stride(sstate.addr_history);

    // --- Pointer PC frequency ---
    uint64_t pc_hash = PC & 0xFFF;
    sstate.pointer_pc_freq[pc_hash]++;
    // Maintain window size for pointer PC freq
    if (sstate.pointer_pc_freq.size() > POINTER_PC_WINDOW) {
        // Remove least used
        uint64_t min_pc = 0; int min_count = 100000;
        for (auto& kv : sstate.pointer_pc_freq)
            if (kv.second < min_count) { min_pc = kv.first; min_count = kv.second; }
        sstate.pointer_pc_freq.erase(min_pc);
    }

    // --- Pointer intensity ---
    int pointer_count = 0;
    for (auto& kv : sstate.pointer_pc_freq) {
        if (kv.second >= 2) pointer_count++;
    }
    sstate.pointer_intensity = pointer_count;

    // --- Mark line as pointer-chasing if PC is frequent in set ---
    lstates[way].last_pc = PC;
    lstates[way].pointer_pc = is_pointer_pc(PC, sstate);

    lstates[way].tag = paddr;
    lstates[way].valid = 1;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ARP: Total evictions: " << total_evictions << std::endl;
    std::cout << "ARP: LRU evictions: " << lru_evictions << std::endl;
    std::cout << "ARP: Pointer-aware evictions: " << pointer_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "ARP heartbeat: evictions=" << total_evictions
              << " lru=" << lru_evictions
              << " pointer=" << pointer_evictions << std::endl;
}