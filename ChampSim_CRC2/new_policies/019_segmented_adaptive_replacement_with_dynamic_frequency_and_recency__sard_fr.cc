#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int RECENCY_SEGMENT_MIN = 4;
constexpr int FREQUENCY_SEGMENT_MIN = 4;
constexpr int SEGMENT_ADJUST_PERIOD = 128; // accesses per set before adjustment
constexpr int FREQUENCY_PROMOTE_THRESHOLD = 2; // hits before promotion
constexpr int STRIDE_HISTORY_LEN = 8;

// Per-line state
struct LineState {
    uint64_t tag;
    uint8_t valid;
    uint8_t lru_position; // within segment
    uint16_t hit_count;   // frequency counter
    bool in_frequency;    // true if in frequency segment
};

// Per-set state
struct SetState {
    int recency_size;
    int frequency_size;
    int access_count;
    int recent_hits;
    int recent_misses;
    std::vector<uint64_t> addr_history;
    int stride; // detected stride (0 if irregular)
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t total_evictions = 0;
uint64_t recency_evictions = 0;
uint64_t frequency_evictions = 0;
uint64_t promotions = 0;
uint64_t demotions = 0;

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
            line_states[set][way].lru_position = way;
            line_states[set][way].hit_count = 0;
            line_states[set][way].in_frequency = false;
        }
        set_states[set].recency_size = LLC_WAYS / 2;
        set_states[set].frequency_size = LLC_WAYS - set_states[set].recency_size;
        set_states[set].access_count = 0;
        set_states[set].recent_hits = 0;
        set_states[set].recent_misses = 0;
        set_states[set].addr_history.clear();
        set_states[set].stride = 0;
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

    // Victim selection: prefer recency segment
    int recency_count = 0, freq_count = 0;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].in_frequency) freq_count++;
        else recency_count++;
    }

    // If recency segment is underutilized, evict from frequency segment
    if (recency_count < RECENCY_SEGMENT_MIN) {
        // Evict lowest hit_count in frequency segment
        int victim = -1, min_hits = 0xFFFF;
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (lstates[way].in_frequency && lstates[way].hit_count < min_hits) {
                min_hits = lstates[way].hit_count;
                victim = way;
            }
        }
        if (victim != -1) {
            frequency_evictions++;
            total_evictions++;
            return victim;
        }
    }

    // Otherwise, evict LRU in recency segment
    int victim = -1, max_lru = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (!lstates[way].in_frequency && lstates[way].lru_position > max_lru) {
            max_lru = lstates[way].lru_position;
            victim = way;
        }
    }
    if (victim != -1) {
        recency_evictions++;
        total_evictions++;
        return victim;
    }

    // Fallback: evict LRU overall
    max_lru = -1;
    victim = 0;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].lru_position > max_lru) {
            max_lru = lstates[way].lru_position;
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

    // --- LRU stack update within segment ---
    bool in_freq = lstates[way].in_frequency;
    uint8_t old_pos = lstates[way].lru_position;
    for (int i = 0; i < LLC_WAYS; ++i) {
        if (lstates[i].in_frequency == in_freq && lstates[i].lru_position < old_pos)
            lstates[i].lru_position++;
    }
    lstates[way].lru_position = 0;

    // --- Frequency counter ---
    if (hit) {
        lstates[way].hit_count++;
        sstate.recent_hits++;
        // Promote to frequency segment if hit_count threshold reached and not already there
        if (!lstates[way].in_frequency && lstates[way].hit_count >= FREQUENCY_PROMOTE_THRESHOLD) {
            lstates[way].in_frequency = true;
            promotions++;
            // Demote LRU in frequency segment if overflow
            int freq_count = 0;
            for (int i = 0; i < LLC_WAYS; ++i)
                if (lstates[i].in_frequency) freq_count++;
            if (freq_count > sstate.frequency_size) {
                // Find LRU in frequency segment and demote
                int lru_freq = -1, lru_way = -1;
                for (int i = 0; i < LLC_WAYS; ++i) {
                    if (lstates[i].in_frequency && lstates[i].lru_position > lru_freq) {
                        lru_freq = lstates[i].lru_position;
                        lru_way = i;
                    }
                }
                if (lru_way != -1) {
                    lstates[lru_way].in_frequency = false;
                    lstates[lru_way].hit_count = 0; // reset on demotion
                    demotions++;
                }
            }
        }
    } else {
        lstates[way].hit_count = 0;
        sstate.recent_misses++;
        lstates[way].in_frequency = false;
    }

    // --- Address history for stride detection ---
    if (sstate.addr_history.size() >= STRIDE_HISTORY_LEN)
        sstate.addr_history.erase(sstate.addr_history.begin());
    sstate.addr_history.push_back(paddr);
    sstate.stride = detect_stride(sstate.addr_history);

    // --- Dynamic segment adjustment ---
    sstate.access_count++;
    if (sstate.access_count % SEGMENT_ADJUST_PERIOD == 0) {
        // If stride detected or hit rate high, expand frequency segment
        int total = sstate.recent_hits + sstate.recent_misses;
        double hit_rate = total ? (double)sstate.recent_hits / total : 0.0;
        if (sstate.stride != 0 || hit_rate > 0.5) {
            if (sstate.frequency_size < LLC_WAYS - RECENCY_SEGMENT_MIN)
                sstate.frequency_size++;
            if (sstate.recency_size > RECENCY_SEGMENT_MIN)
                sstate.recency_size--;
        } else {
            // Shrink frequency segment if hit rate low or stride irregular
            if (sstate.frequency_size > FREQUENCY_SEGMENT_MIN)
                sstate.frequency_size--;
            if (sstate.recency_size < LLC_WAYS - FREQUENCY_SEGMENT_MIN)
                sstate.recency_size++;
        }
        sstate.recent_hits = 0;
        sstate.recent_misses = 0;
    }

    lstates[way].tag = paddr;
    lstates[way].valid = 1;
}

void PrintStats() {
    std::cout << "SARD-FR: Total evictions: " << total_evictions << std::endl;
    std::cout << "SARD-FR: Recency evictions: " << recency_evictions << std::endl;
    std::cout << "SARD-FR: Frequency evictions: " << frequency_evictions << std::endl;
    std::cout << "SARD-FR: Promotions: " << promotions << std::endl;
    std::cout << "SARD-FR: Demotions: " << demotions << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "SARD-FR heartbeat: evictions=" << total_evictions
              << " recency=" << recency_evictions
              << " frequency=" << frequency_evictions
              << " promotions=" << promotions
              << " demotions=" << demotions << std::endl;
}