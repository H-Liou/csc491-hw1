#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int REUSE_BITS = 4;           // Per-line reuse interval counter (0-15)
constexpr int STRIDE_HISTORY = 8;       // Number of last addresses per set for stride detection
constexpr int STRIDE_THRESHOLD = 6;     // If >= threshold strides are equal, treat as regular
constexpr int INTERVAL_THRESHOLD = 3;   // Evict blocks with longest predicted reuse interval

enum ARIPMode { INTERVAL_MODE, RECENCY_MODE };

// Per-line state
struct LineState {
    uint64_t tag;
    uint64_t last_addr;
    int reuse_interval;    // Predicted reuse interval
    int lru_position;      // LRU stack position
    uint8_t valid;
};

// Per-set state
struct SetState {
    ARIPMode mode;
    std::vector<uint64_t> addr_history; // For stride detection
    int stride_count;
    uint64_t last_stride;
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t interval_evictions = 0;
uint64_t recency_evictions = 0;
uint64_t total_evictions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].last_addr = 0;
            line_states[set][way].reuse_interval = 0;
            line_states[set][way].lru_position = way;
            line_states[set][way].valid = 0;
        }
        set_states[set].mode = RECENCY_MODE;
        set_states[set].addr_history.assign(STRIDE_HISTORY, 0);
        set_states[set].stride_count = 0;
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

    uint32_t victim = 0;

    if (sstate.mode == INTERVAL_MODE) {
        // Evict block with largest predicted reuse interval; break ties by LRU
        int max_interval = lstates[0].reuse_interval;
        int max_lru = lstates[0].lru_position;
        victim = 0;
        for (int way = 1; way < LLC_WAYS; ++way) {
            if (!lstates[way].valid) {
                victim = way;
                break;
            }
            if (lstates[way].reuse_interval > max_interval ||
                (lstates[way].reuse_interval == max_interval && lstates[way].lru_position > max_lru)) {
                max_interval = lstates[way].reuse_interval;
                max_lru = lstates[way].lru_position;
                victim = way;
            }
        }
        interval_evictions++;
    } else {
        // RECENCY_MODE: Evict LRU block
        int max_lru = lstates[0].lru_position;
        victim = 0;
        for (int way = 1; way < LLC_WAYS; ++way) {
            if (!lstates[way].valid) {
                victim = way;
                break;
            }
            if (lstates[way].lru_position > max_lru) {
                max_lru = lstates[way].lru_position;
                victim = way;
            }
        }
        recency_evictions++;
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

    // --- Update per-line reuse interval ---
    if (hit) {
        lstates[way].reuse_interval = 0;
    } else {
        lstates[way].reuse_interval = std::min(lstates[way].reuse_interval + 1, (1 << REUSE_BITS) - 1);
    }

    // --- Update LRU stack positions ---
    int prev_lru = lstates[way].lru_position;
    for (int i = 0; i < LLC_WAYS; ++i) {
        if (lstates[i].lru_position < prev_lru)
            lstates[i].lru_position++;
    }
    lstates[way].lru_position = 0;

    // --- Update per-line last_addr and valid ---
    lstates[way].last_addr = paddr;
    lstates[way].tag = paddr;
    lstates[way].valid = 1;

    // --- Stride detection for set mode ---
    sstate.addr_history.erase(sstate.addr_history.begin());
    sstate.addr_history.push_back(paddr);

    // Detect if strides are regular
    sstate.stride_count = 0;
    uint64_t stride = 0;
    bool first = true;
    for (size_t i = 1; i < sstate.addr_history.size(); ++i) {
        uint64_t cur_stride = sstate.addr_history[i] - sstate.addr_history[i-1];
        if (first) {
            stride = cur_stride;
            first = false;
        }
        if (cur_stride == stride)
            sstate.stride_count++;
    }
    // If stride_count exceeds threshold, switch to INTERVAL_MODE
    if (sstate.stride_count >= STRIDE_THRESHOLD)
        sstate.mode = INTERVAL_MODE;
    else
        sstate.mode = RECENCY_MODE;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ARIP: Total evictions: " << total_evictions << std::endl;
    std::cout << "ARIP: Interval evictions: " << interval_evictions << std::endl;
    std::cout << "ARIP: Recency evictions: " << recency_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "ARIP heartbeat: evictions=" << total_evictions
              << " interval=" << interval_evictions
              << " recency=" << recency_evictions << std::endl;
}