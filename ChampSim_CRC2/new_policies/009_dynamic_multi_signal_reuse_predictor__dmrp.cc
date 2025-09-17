#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int FREQ_BITS = 4;          // Frequency counter per line (0-15)
constexpr int PC_HISTORY_LEN = 8;     // Number of recent PCs per set
constexpr int PHASE_WINDOW = 32;      // Number of accesses per phase
constexpr int REGULARITY_THRESHOLD = 24; // If > threshold accesses are regular, prefer frequency

enum PhaseMode { FREQ_DOMINANT, PC_DOMINANT };

// Per-line state
struct LineState {
    uint64_t tag;
    uint64_t last_PC;
    int freq_count;   // Frequency counter
    int lru_position; // LRU stack position
};

// Per-set state
struct SetState {
    PhaseMode mode;
    std::vector<uint64_t> recent_pcs; // For PC-dominant mode
    int regular_accesses;             // Count of regular accesses in window
    int total_accesses;               // Total accesses in window
    uint64_t last_addr;
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t freq_evictions = 0;
uint64_t pc_evictions = 0;
uint64_t total_evictions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].last_PC = 0;
            line_states[set][way].freq_count = 0;
            line_states[set][way].lru_position = way;
        }
        set_states[set].mode = FREQ_DOMINANT;
        set_states[set].recent_pcs.assign(PC_HISTORY_LEN, 0);
        set_states[set].regular_accesses = 0;
        set_states[set].total_accesses = 0;
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
    auto& sstate = set_states[set];
    auto& lstates = line_states[set];

    uint32_t victim = 0;

    if (sstate.mode == FREQ_DOMINANT) {
        // Evict block with lowest freq_count; break ties by LRU
        int min_freq = lstates[0].freq_count;
        int min_lru = lstates[0].lru_position;
        victim = 0;
        for (int way = 1; way < LLC_WAYS; ++way) {
            if (lstates[way].freq_count < min_freq ||
                (lstates[way].freq_count == min_freq && lstates[way].lru_position > min_lru)) {
                min_freq = lstates[way].freq_count;
                min_lru = lstates[way].lru_position;
                victim = way;
            }
        }
        freq_evictions++;
    } else {
        // PC-dominant: Evict block whose last_PC is least recently seen in recent_pcs; break ties by LRU
        int oldest_pc_idx = -1;
        int oldest_pc_pos = PC_HISTORY_LEN;
        int min_lru = lstates[0].lru_position;
        victim = 0;
        for (int way = 0; way < LLC_WAYS; ++way) {
            auto it = std::find(sstate.recent_pcs.begin(), sstate.recent_pcs.end(), lstates[way].last_PC);
            int pos = (it != sstate.recent_pcs.end()) ? std::distance(sstate.recent_pcs.begin(), it) : PC_HISTORY_LEN;
            if (pos > oldest_pc_pos ||
                (pos == oldest_pc_pos && lstates[way].lru_position > min_lru)) {
                oldest_pc_pos = pos;
                min_lru = lstates[way].lru_position;
                victim = way;
            }
        }
        pc_evictions++;
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
    auto& sstate = set_states[set];
    auto& lstates = line_states[set];

    // --- Update per-line frequency ---
    if (hit)
        lstates[way].freq_count = std::min(lstates[way].freq_count + 1, (1 << FREQ_BITS) - 1);
    else
        lstates[way].freq_count = std::max(lstates[way].freq_count - 1, 0);

    // --- Update LRU stack positions ---
    int prev_lru = lstates[way].lru_position;
    for (int i = 0; i < LLC_WAYS; ++i) {
        if (lstates[i].lru_position < prev_lru)
            lstates[i].lru_position++;
    }
    lstates[way].lru_position = 0;

    // --- Update per-line last_PC ---
    lstates[way].last_PC = PC;

    // --- Update per-set PC history ---
    sstate.recent_pcs.erase(sstate.recent_pcs.begin());
    sstate.recent_pcs.push_back(PC);

    // --- Phase detection: regularity check ---
    sstate.total_accesses++;
    if (sstate.last_addr != 0 && (paddr - sstate.last_addr) % 64 == 0)
        sstate.regular_accesses++;
    sstate.last_addr = paddr;

    if (sstate.total_accesses >= PHASE_WINDOW) {
        // If regular accesses dominate, use FREQ_DOMINANT; else PC_DOMINANT
        if (sstate.regular_accesses >= REGULARITY_THRESHOLD)
            sstate.mode = FREQ_DOMINANT;
        else
            sstate.mode = PC_DOMINANT;
        sstate.regular_accesses = 0;
        sstate.total_accesses = 0;
    }

    // --- Update per-line tag ---
    lstates[way].tag = paddr;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DMRP: Total evictions: " << total_evictions << std::endl;
    std::cout << "DMRP: Freq evictions: " << freq_evictions << std::endl;
    std::cout << "DMRP: PC evictions: " << pc_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DMRP heartbeat: evictions=" << total_evictions
              << " freq=" << freq_evictions
              << " pc=" << pc_evictions << std::endl;
}