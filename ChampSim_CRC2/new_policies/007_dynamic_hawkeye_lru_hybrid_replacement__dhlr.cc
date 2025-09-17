#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int HISTORY_LENGTH = 128;      // Per-set history window for phase detection
constexpr int CONFIDENCE_THRESHOLD = 96; // If prediction accuracy > threshold, use Hawkeye

// Per-line state
struct LineState {
    uint64_t signature; // PC signature for Hawkeye
    bool cache_friendly; // Hawkeye prediction: true=retain, false=evict
    uint8_t lru_position; // LRU stack position (0=MRU, LLC_WAYS-1=LRU)
};

// Per-set state
struct SetState {
    std::vector<uint8_t> recent_hits; // Circular buffer: 1=hit, 0=miss
    uint32_t history_ptr;
    uint32_t prediction_hits;
    uint32_t prediction_total;
    bool use_hawkeye; // True: use Hawkeye, False: use LRU
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Simple global Hawkeye predictor: signature -> cache-friendliness
std::unordered_map<uint64_t, bool> hawkeye_table; // PC signature -> prediction

// Telemetry
uint64_t total_evictions = 0;
uint64_t hawkeye_evictions = 0;
uint64_t lru_evictions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].signature = 0;
            line_states[set][way].cache_friendly = false;
            line_states[set][way].lru_position = way;
        }
        set_states[set].recent_hits.assign(HISTORY_LENGTH, 0);
        set_states[set].history_ptr = 0;
        set_states[set].prediction_hits = 0;
        set_states[set].prediction_total = 0;
        set_states[set].use_hawkeye = true;
    }
}

// Find victim using Hawkeye or fallback to LRU
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

    // Use Hawkeye if prediction accuracy is high
    if (sstate.use_hawkeye) {
        // Prefer to evict cache-averse lines (cache_friendly==false)
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (!lstates[way].cache_friendly) {
                hawkeye_evictions++;
                total_evictions++;
                return way;
            }
        }
        // If all lines are predicted friendly, evict LRU
        int lru_way = 0;
        uint8_t max_lru = 0;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (lstates[way].lru_position > max_lru) {
                max_lru = lstates[way].lru_position;
                lru_way = way;
            }
        }
        hawkeye_evictions++;
        total_evictions++;
        return lru_way;
    } else {
        // Fallback: pure LRU
        int lru_way = 0;
        uint8_t max_lru = 0;
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

    // --- Update LRU stack ---
    uint8_t old_pos = lstates.lru_position;
    for (int w = 0; w < LLC_WAYS; ++w) {
        if (line_states[set][w].lru_position < old_pos)
            line_states[set][w].lru_position++;
    }
    lstates.lru_position = 0;

    // --- Update Hawkeye predictor ---
    lstates.signature = PC; // Use PC as signature
    bool predicted_friendly = false;
    auto it = hawkeye_table.find(PC);
    if (it != hawkeye_table.end())
        predicted_friendly = it->second;

    // On hit: mark as cache-friendly, update predictor
    if (hit) {
        lstates.cache_friendly = true;
        hawkeye_table[PC] = true;
        sstate.recent_hits[sstate.history_ptr] = 1;
        sstate.prediction_hits++;
    } else {
        lstates.cache_friendly = predicted_friendly;
        hawkeye_table[PC] = false;
        sstate.recent_hits[sstate.history_ptr] = 0;
    }
    sstate.history_ptr = (sstate.history_ptr + 1) % HISTORY_LENGTH;
    sstate.prediction_total++;

    // --- Adapt: switch between Hawkeye and LRU based on prediction accuracy ---
    int hit_count = 0;
    for (int i = 0; i < HISTORY_LENGTH; ++i)
        hit_count += sstate.recent_hits[i];
    sstate.use_hawkeye = (hit_count > CONFIDENCE_THRESHOLD);

    // If phase is irregular, LRU is more robust; if regular, Hawkeye can exploit reuse
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DHLR: Total evictions: " << total_evictions << std::endl;
    std::cout << "DHLR: Hawkeye evictions: " << hawkeye_evictions << std::endl;
    std::cout << "DHLR: LRU evictions: " << lru_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DHLR heartbeat: evictions=" << total_evictions
              << " hawkeye_evictions=" << hawkeye_evictions
              << " lru_evictions=" << lru_evictions << std::endl;
}