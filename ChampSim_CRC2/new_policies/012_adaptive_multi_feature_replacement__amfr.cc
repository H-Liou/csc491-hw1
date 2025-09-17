#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int STRIDE_HISTORY = 8;      // Per-set address history size
constexpr int IRR_PC_TABLE_SIZE = 16;  // Per-set irregular PC table size
constexpr int IRR_PC_PROTECT = 3;      // Protect threshold for irregular PCs

struct LineState {
    uint64_t tag;
    uint8_t valid;
    int lru_position;
    bool stride_protect;
    bool irr_protect;
    uint64_t last_addr;
    uint64_t last_pc;
};

struct SetState {
    std::vector<uint64_t> addr_history; // Last STRIDE_HISTORY addresses
    int detected_stride;
    std::unordered_map<uint64_t, int> irr_pc_table; // PC -> count
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t total_evictions = 0;
uint64_t stride_protected_evictions = 0;
uint64_t irr_protected_evictions = 0;
uint64_t lru_evictions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].valid = 0;
            line_states[set][way].lru_position = way;
            line_states[set][way].stride_protect = false;
            line_states[set][way].irr_protect = false;
            line_states[set][way].last_addr = 0;
            line_states[set][way].last_pc = 0;
        }
        set_states[set].addr_history.clear();
        set_states[set].detected_stride = 0;
        set_states[set].irr_pc_table.clear();
    }
}

// Helper: Detect stride in recent address history
int detect_stride(const std::vector<uint64_t>& history) {
    if (history.size() < 3) return 0;
    int64_t stride = history[1] - history[0];
    for (size_t i = 2; i < history.size(); ++i) {
        if ((int64_t)(history[i] - history[i-1]) != stride)
            return 0;
    }
    return (int)stride;
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

    // 2. Try to find a block with neither stride nor irregular protection
    int lru_max = -1, victim = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (!lstates[way].stride_protect && !lstates[way].irr_protect) {
            if (lstates[way].lru_position > lru_max) {
                lru_max = lstates[way].lru_position;
                victim = way;
            }
        }
    }
    if (victim != -1) {
        lru_evictions++;
        total_evictions++;
        return victim;
    }

    // 3. If all are protected, evict block with lowest protection (prefer LRU among protected)
    int min_protect = 3, max_lru = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        int prot = (lstates[way].stride_protect ? 1 : 0) + (lstates[way].irr_protect ? 2 : 0);
        if (prot < min_protect || (prot == min_protect && lstates[way].lru_position > max_lru)) {
            min_protect = prot;
            max_lru = lstates[way].lru_position;
            victim = way;
        }
    }
    if (min_protect & 1) stride_protected_evictions++;
    if (min_protect & 2) irr_protected_evictions++;
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
    // Hash PC to a small table to detect pointer-chasing or irregular code
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
    lstates[way].irr_protect = (pc_table[pc_hash] >= IRR_PC_PROTECT);

    // Optional: decay protection for blocks not hit recently
    if (!hit) {
        lstates[way].stride_protect = false;
        lstates[way].irr_protect = false;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "AMFR: Total evictions: " << total_evictions << std::endl;
    std::cout << "AMFR: Stride-protected evictions: " << stride_protected_evictions << std::endl;
    std::cout << "AMFR: Irregular-protected evictions: " << irr_protected_evictions << std::endl;
    std::cout << "AMFR: LRU evictions: " << lru_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "AMFR heartbeat: evictions=" << total_evictions
              << " stride=" << stride_protected_evictions
              << " irr=" << irr_protected_evictions
              << " lru=" << lru_evictions << std::endl;
}