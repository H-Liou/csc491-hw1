#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr uint8_t FREQ_MAX = 15;
constexpr uint8_t FREQ_MIN = 0;
constexpr uint8_t RECENCY_MAX = 255;
constexpr uint8_t RECENCY_MIN = 0;
constexpr uint8_t HOT_SEGMENT_SIZE = 6; // Number of "hot" ways per set
constexpr uint8_t PHASE_WINDOW = 32;    // Window for phase detection

struct LineState {
    uint64_t tag;
    uint8_t valid;
    uint8_t freq;      // Frequency counter (LFU)
    uint8_t recency;   // Recency timestamp (LRU)
    uint8_t hot;       // 1 if in hot segment, 0 if cold
};

struct SetState {
    uint32_t timestamp; // For recency aging
    uint16_t recent_hits; // For phase detection
    uint16_t recent_misses;
    uint8_t phase_ptr;
    uint8_t phase_history[PHASE_WINDOW];
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t total_evictions = 0;
uint64_t hot_evictions = 0;
uint64_t cold_evictions = 0;
uint64_t hot_promotions = 0;
uint64_t hot_demotions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].valid = 0;
            line_states[set][way].freq = 0;
            line_states[set][way].recency = RECENCY_MAX;
            line_states[set][way].hot = 0;
        }
        set_states[set].timestamp = 0;
        set_states[set].recent_hits = 0;
        set_states[set].recent_misses = 0;
        set_states[set].phase_ptr = 0;
        std::memset(set_states[set].phase_history, 0, sizeof(set_states[set].phase_history));
    }
}

// Helper: Detect phase change (drop in hit rate)
bool phase_change(const SetState& sstate) {
    int sum = 0;
    for (int i = 0; i < PHASE_WINDOW; ++i)
        sum += sstate.phase_history[i];
    return sum < PHASE_WINDOW / 4; // If <25% hits in window, phase change
}

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

    // Step 1: Prefer invalid way
    for (int way = 0; way < LLC_WAYS; ++way)
        if (!lstates[way].valid)
            return way;

    // Step 2: If phase change detected, demote oldest hot block
    if (phase_change(sstate)) {
        int victim = -1;
        uint8_t oldest = RECENCY_MIN - 1;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (lstates[way].hot && lstates[way].recency > oldest) {
                oldest = lstates[way].recency;
                victim = way;
            }
        }
        if (victim != -1) {
            hot_demotions++;
            total_evictions++;
            return victim;
        }
    }

    // Step 3: Evict cold block with lowest frequency, oldest recency
    int victim = -1;
    uint8_t min_freq = FREQ_MAX + 1;
    uint8_t oldest = RECENCY_MIN - 1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (!lstates[way].hot) {
            if (lstates[way].freq < min_freq ||
                (lstates[way].freq == min_freq && lstates[way].recency > oldest)) {
                min_freq = lstates[way].freq;
                oldest = lstates[way].recency;
                victim = way;
            }
        }
    }
    if (victim != -1) {
        cold_evictions++;
        total_evictions++;
        return victim;
    }

    // Step 4: Fallback: evict hot block with lowest frequency, oldest recency
    min_freq = FREQ_MAX + 1;
    oldest = RECENCY_MIN - 1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].hot) {
            if (lstates[way].freq < min_freq ||
                (lstates[way].freq == min_freq && lstates[way].recency > oldest)) {
                min_freq = lstates[way].freq;
                oldest = lstates[way].recency;
                victim = way;
            }
        }
    }
    if (victim != -1) {
        hot_evictions++;
        total_evictions++;
        return victim;
    }

    // Step 5: Fallback to LRU (oldest recency)
    oldest = RECENCY_MIN - 1;
    victim = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].recency > oldest) {
            oldest = lstates[way].recency;
            victim = way;
        }
    }
    total_evictions++;
    return victim;
}

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

    // --- Update recency timestamp ---
    sstate.timestamp++;
    lstates[way].recency = sstate.timestamp;

    // --- Update frequency counter ---
    if (hit) {
        if (lstates[way].freq < FREQ_MAX)
            lstates[way].freq++;
        sstate.recent_hits++;
        sstate.phase_history[sstate.phase_ptr] = 1;
    } else {
        if (lstates[way].freq > FREQ_MIN)
            lstates[way].freq--;
        sstate.recent_misses++;
        sstate.phase_history[sstate.phase_ptr] = 0;
    }
    sstate.phase_ptr = (sstate.phase_ptr + 1) % PHASE_WINDOW;

    // --- Hot/cold segment management ---
    // Promote to hot if freq exceeds threshold, demote if freq drops
    if (lstates[way].freq >= FREQ_MAX / 2 && !lstates[way].hot) {
        // Only promote if hot segment has space
        int hot_count = 0;
        for (int i = 0; i < LLC_WAYS; ++i)
            hot_count += lstates[i].hot;
        if (hot_count < HOT_SEGMENT_SIZE) {
            lstates[way].hot = 1;
            hot_promotions++;
        }
    } else if (lstates[way].freq < FREQ_MAX / 4 && lstates[way].hot) {
        lstates[way].hot = 0;
        hot_demotions++;
    }

    lstates[way].tag = paddr;
    lstates[way].valid = 1;
}

void PrintStats() {
    std::cout << "PASFR: Total evictions: " << total_evictions << std::endl;
    std::cout << "PASFR: Hot evictions: " << hot_evictions << std::endl;
    std::cout << "PASFR: Cold evictions: " << cold_evictions << std::endl;
    std::cout << "PASFR: Hot promotions: " << hot_promotions << std::endl;
    std::cout << "PASFR: Hot demotions: " << hot_demotions << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "PASFR heartbeat: evictions=" << total_evictions
              << " hot_evictions=" << hot_evictions
              << " cold_evictions=" << cold_evictions
              << " hot_promotions=" << hot_promotions
              << " hot_demotions=" << hot_demotions << std::endl;
}