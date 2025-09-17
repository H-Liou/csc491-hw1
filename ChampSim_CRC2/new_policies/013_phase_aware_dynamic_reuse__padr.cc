#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int REUSE_TABLE_SIZE = 8;      // Per-set reuse table size
constexpr int PHASE_WINDOW = 32;         // Number of accesses to consider for phase
constexpr int STRIDE_HISTORY = 8;        // For stride detection
constexpr int IRR_PC_TABLE_SIZE = 16;    // For irregular PC tracking
constexpr int IRR_PC_THRESHOLD = 3;      // Protection threshold

enum PhaseType { PHASE_UNKNOWN, PHASE_REGULAR, PHASE_IRREGULAR, PHASE_MIXED };

struct LineState {
    uint64_t tag;
    uint8_t valid;
    int lru_position;
    int reuse_counter;         // Distance since last access
    bool stride_protect;
    bool irr_protect;
    uint64_t last_addr;
    uint64_t last_pc;
};

struct SetState {
    std::vector<uint64_t> addr_history;           // For stride detection
    int detected_stride;
    std::unordered_map<uint64_t, int> irr_pc_table; // PC -> count
    std::vector<uint64_t> phase_addr_window;      // For phase detection
    PhaseType phase;
    int phase_regular_score;
    int phase_irregular_score;
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

// Helper: Detect phase (regular/irregular/mixed) in a set
PhaseType detect_phase(const std::vector<uint64_t>& window) {
    if (window.size() < 4) return PHASE_UNKNOWN;
    // Regular: >75% accesses have same stride
    std::unordered_map<int64_t, int> stride_count;
    for (size_t i = 1; i < window.size(); ++i)
        stride_count[(int64_t)(window[i] - window[i-1])]++;
    int max_count = 0;
    for (auto& kv : stride_count) max_count = std::max(max_count, kv.second);
    if (max_count >= (int)(0.75 * (window.size()-1)))
        return PHASE_REGULAR;
    // Irregular: >50% accesses have unique strides
    if (stride_count.size() > (window.size()-1)/2)
        return PHASE_IRREGULAR;
    return PHASE_MIXED;
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
            line_states[set][way].reuse_counter = 0;
            line_states[set][way].stride_protect = false;
            line_states[set][way].irr_protect = false;
            line_states[set][way].last_addr = 0;
            line_states[set][way].last_pc = 0;
        }
        set_states[set].addr_history.clear();
        set_states[set].detected_stride = 0;
        set_states[set].irr_pc_table.clear();
        set_states[set].phase_addr_window.clear();
        set_states[set].phase = PHASE_UNKNOWN;
        set_states[set].phase_regular_score = 0;
        set_states[set].phase_irregular_score = 0;
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

    // 2. Use phase to guide victim selection
    if (sstate.phase == PHASE_REGULAR) {
        // Regular: Evict block with longest reuse distance and not stride protected
        int max_reuse = -1, victim = -1;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (!lstates[way].stride_protect) {
                if (lstates[way].reuse_counter > max_reuse) {
                    max_reuse = lstates[way].reuse_counter;
                    victim = way;
                }
            }
        }
        if (victim != -1) {
            regular_evictions++;
            total_evictions++;
            return victim;
        }
    } else if (sstate.phase == PHASE_IRREGULAR) {
        // Irregular: Evict block not irregular protected, prefer LRU among those
        int max_lru = -1, victim = -1;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (!lstates[way].irr_protect) {
                if (lstates[way].lru_position > max_lru) {
                    max_lru = lstates[way].lru_position;
                    victim = way;
                }
            }
        }
        if (victim != -1) {
            irregular_evictions++;
            total_evictions++;
            return victim;
        }
    } else {
        // Mixed or unknown: Evict block with highest reuse counter and not protected
        int max_reuse = -1, victim = -1;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (!lstates[way].stride_protect && !lstates[way].irr_protect) {
                if (lstates[way].reuse_counter > max_reuse) {
                    max_reuse = lstates[way].reuse_counter;
                    victim = way;
                }
            }
        }
        if (victim != -1) {
            reuse_evictions++;
            total_evictions++;
            return victim;
        }
    }

    // 3. If all are protected, evict LRU among protected
    int max_lru = -1, victim = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].lru_position > max_lru) {
            max_lru = lstates[way].lru_position;
            victim = way;
        }
    }
    lru_evictions++;
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
    lstates[way].last_addr = paddr;
    lstates[way].last_pc = PC;

    // Update LRU positions
    int prev_lru = lstates[way].lru_position;
    for (int i = 0; i < LLC_WAYS; ++i)
        if (lstates[i].lru_position < prev_lru)
            lstates[i].lru_position++;
    lstates[way].lru_position = 0;

    // --- Reuse interval tracking ---
    // Increment reuse counters for all, reset for the accessed block
    for (int i = 0; i < LLC_WAYS; ++i)
        lstates[i].reuse_counter++;
    lstates[way].reuse_counter = 0;

    // --- Stride detection ---
    if (sstate.addr_history.size() >= STRIDE_HISTORY)
        sstate.addr_history.erase(sstate.addr_history.begin());
    sstate.addr_history.push_back(paddr);
    sstate.detected_stride = detect_stride(sstate.addr_history);

    // Mark stride-protected if stride detected and block matches stride
    lstates[way].stride_protect = false;
    if (sstate.detected_stride != 0 && sstate.addr_history.size() >= 2) {
        uint64_t prev_addr = sstate.addr_history[sstate.addr_history.size()-2];
        if ((int64_t)(paddr - prev_addr) == sstate.detected_stride)
            lstates[way].stride_protect = true;
    }

    // --- Irregular PC tracking ---
    uint64_t pc_hash = PC & 0xFFF;
    auto& pc_table = sstate.irr_pc_table;
    pc_table[pc_hash]++;
    if (pc_table.size() > IRR_PC_TABLE_SIZE) {
        // Remove least used
        uint64_t min_pc = 0; int min_count = 100000;
        for (auto& kv : pc_table)
            if (kv.second < min_count) { min_pc = kv.first; min_count = kv.second; }
        pc_table.erase(min_pc);
    }
    lstates[way].irr_protect = (pc_table[pc_hash] >= IRR_PC_THRESHOLD);

    // --- Phase detection: update window and recompute phase ---
    if (sstate.phase_addr_window.size() >= PHASE_WINDOW)
        sstate.phase_addr_window.erase(sstate.phase_addr_window.begin());
    sstate.phase_addr_window.push_back(paddr);
    sstate.phase = detect_phase(sstate.phase_addr_window);

    // Optional: decay protection for blocks not hit recently
    if (!hit) {
        lstates[way].stride_protect = false;
        lstates[way].irr_protect = false;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "PADR: Total evictions: " << total_evictions << std::endl;
    std::cout << "PADR: Regular phase evictions: " << regular_evictions << std::endl;
    std::cout << "PADR: Irregular phase evictions: " << irregular_evictions << std::endl;
    std::cout << "PADR: Reuse-based evictions: " << reuse_evictions << std::endl;
    std::cout << "PADR: LRU evictions: " << lru_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "PADR heartbeat: evictions=" << total_evictions
              << " regular=" << regular_evictions
              << " irregular=" << irregular_evictions
              << " reuse=" << reuse_evictions
              << " lru=" << lru_evictions << std::endl;
}