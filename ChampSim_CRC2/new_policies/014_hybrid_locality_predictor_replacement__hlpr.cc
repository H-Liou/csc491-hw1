#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int STRIDE_HISTORY = 8;
constexpr int IRR_PC_TABLE_SIZE = 16;
constexpr int IRR_PC_THRESHOLD = 3;
constexpr int SPATIAL_WINDOW = 8;
constexpr int REUSE_MAX = 255;

struct LineState {
    uint64_t tag;
    uint8_t valid;
    int lru_position;
    uint8_t reuse_counter;      // Recency
    bool spatial_local;         // Protected by spatial locality
    bool irregular_local;       // Protected by irregular access
    uint64_t last_addr;
    uint64_t last_pc;
};

struct SetState {
    std::vector<uint64_t> addr_history;           // For stride/spatial detection
    int detected_stride;
    std::unordered_map<uint64_t, int> irr_pc_table; // PC -> count
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t total_evictions = 0;
uint64_t spatial_evictions = 0;
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

// Helper: Detect spatial neighbor (accesses within block size vicinity)
bool is_spatial_neighbor(const std::vector<uint64_t>& history, uint64_t addr) {
    if (history.empty()) return false;
    uint64_t block_size = 64; // Assume 64B block
    for (auto prev_addr : history) {
        if (std::abs((int64_t)addr - (int64_t)prev_addr) <= (int64_t)block_size)
            return true;
    }
    return false;
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
            line_states[set][way].reuse_counter = REUSE_MAX;
            line_states[set][way].spatial_local = false;
            line_states[set][way].irregular_local = false;
            line_states[set][way].last_addr = 0;
            line_states[set][way].last_pc = 0;
        }
        set_states[set].addr_history.clear();
        set_states[set].detected_stride = 0;
        set_states[set].irr_pc_table.clear();
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

    // 1. Prefer invalid block
    for (int way = 0; way < LLC_WAYS; ++way)
        if (!lstates[way].valid)
            return way;

    // 2. Evict block with lowest reuse and no locality protection
    int max_reuse = -1, victim = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (!lstates[way].spatial_local && !lstates[way].irregular_local) {
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

    // 3. If all are protected, evict block with lowest protection priority
    // Prefer to evict blocks with only one type of protection (spatial or irregular)
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].spatial_local && !lstates[way].irregular_local) {
            spatial_evictions++;
            total_evictions++;
            return way;
        }
        if (!lstates[way].spatial_local && lstates[way].irregular_local) {
            irregular_evictions++;
            total_evictions++;
            return way;
        }
    }

    // 4. If all are doubly protected, evict LRU among them
    int max_lru = -1; victim = -1;
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
        if (lstates[i].reuse_counter < REUSE_MAX)
            lstates[i].reuse_counter++;
    lstates[way].reuse_counter = 0;

    // --- Stride and spatial locality detection ---
    if (sstate.addr_history.size() >= STRIDE_HISTORY)
        sstate.addr_history.erase(sstate.addr_history.begin());
    sstate.addr_history.push_back(paddr);
    sstate.detected_stride = detect_stride(sstate.addr_history);

    // Mark spatial_local if stride detected or neighbor access
    lstates[way].spatial_local = false;
    if (sstate.detected_stride != 0 && sstate.addr_history.size() >= 2) {
        uint64_t prev_addr = sstate.addr_history[sstate.addr_history.size()-2];
        if ((int64_t)(paddr - prev_addr) == sstate.detected_stride)
            lstates[way].spatial_local = true;
    } else if (is_spatial_neighbor(sstate.addr_history, paddr)) {
        lstates[way].spatial_local = true;
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
    lstates[way].irregular_local = (pc_table[pc_hash] >= IRR_PC_THRESHOLD);

    // Optional: decay protection for blocks not hit recently
    if (!hit) {
        lstates[way].spatial_local = false;
        lstates[way].irregular_local = false;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "HLPR: Total evictions: " << total_evictions << std::endl;
    std::cout << "HLPR: Spatial locality evictions: " << spatial_evictions << std::endl;
    std::cout << "HLPR: Irregular locality evictions: " << irregular_evictions << std::endl;
    std::cout << "HLPR: Reuse-based evictions: " << reuse_evictions << std::endl;
    std::cout << "HLPR: LRU evictions: " << lru_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "HLPR heartbeat: evictions=" << total_evictions
              << " spatial=" << spatial_evictions
              << " irregular=" << irregular_evictions
              << " reuse=" << reuse_evictions
              << " lru=" << lru_evictions << std::endl;
}