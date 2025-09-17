#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int REUSE_HISTORY_LEN = 16;
constexpr int STRIDE_HISTORY_LEN = 8;
constexpr int REGULAR_PHASE_THRESHOLD = 10; // out of REUSE_HISTORY_LEN
constexpr int SPATIAL_ALIGNMENT = 64; // bytes

struct LineState {
    uint64_t tag;
    uint8_t valid;
    uint8_t lru_position;
    uint16_t reuse_counter; // counts hits since insertion
    bool spatial_reuse;     // set if last access was spatially adjacent
};

struct SetState {
    std::vector<uint64_t> addr_history;
    std::vector<int> reuse_history; // 1 if hit, 0 if miss
    int stride; // detected stride (0 if irregular)
    bool regular_phase; // true if regular spatial/temporal locality detected
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t total_evictions = 0;
uint64_t regular_evictions = 0;
uint64_t irregular_evictions = 0;

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
            line_states[set][way].reuse_counter = 0;
            line_states[set][way].spatial_reuse = false;
        }
        set_states[set].addr_history.clear();
        set_states[set].reuse_history.clear();
        set_states[set].stride = 0;
        set_states[set].regular_phase = false;
    }
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

    // Prefer invalid block
    for (int way = 0; way < LLC_WAYS; ++way)
        if (!lstates[way].valid)
            return way;

    // Phase detection
    int stride = sstate.stride;
    int recent_hits = std::count(sstate.reuse_history.begin(), sstate.reuse_history.end(), 1);
    bool regular_phase = (stride != 0) || (recent_hits >= REGULAR_PHASE_THRESHOLD);
    sstate.regular_phase = regular_phase;

    // Regular phase: prioritize low reuse, poor spatial lines
    if (regular_phase) {
        int victim = -1;
        int min_reuse = 0xFFFF;
        for (int way = 0; way < LLC_WAYS; ++way) {
            // Prefer lines with lowest reuse, and not spatially reused
            int reuse = lstates[way].reuse_counter;
            bool spatial = lstates[way].spatial_reuse;
            if (reuse < min_reuse && !spatial) {
                min_reuse = reuse;
                victim = way;
            }
        }
        if (victim != -1) {
            regular_evictions++;
            total_evictions++;
            return victim;
        }
        // If all are spatially reused, evict lowest reuse
        min_reuse = 0xFFFF;
        for (int way = 0; way < LLC_WAYS; ++way) {
            int reuse = lstates[way].reuse_counter;
            if (reuse < min_reuse) {
                min_reuse = reuse;
                victim = way;
            }
        }
        regular_evictions++;
        total_evictions++;
        return victim;
    }

    // Irregular phase: LRU, but protect lines with recent hits
    int lru_way = -1, max_lru = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].reuse_counter == 0 && lstates[way].lru_position > max_lru) {
            max_lru = lstates[way].lru_position;
            lru_way = way;
        }
    }
    if (lru_way != -1) {
        irregular_evictions++;
        total_evictions++;
        return lru_way;
    }
    // If all have reuse, evict highest LRU
    max_lru = -1;
    lru_way = 0;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].lru_position > max_lru) {
            max_lru = lstates[way].lru_position;
            lru_way = way;
        }
    }
    irregular_evictions++;
    total_evictions++;
    return lru_way;
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

    // --- LRU stack update ---
    uint8_t old_pos = lstates[way].lru_position;
    for (int i = 0; i < LLC_WAYS; ++i) {
        if (lstates[i].lru_position < old_pos)
            lstates[i].lru_position++;
    }
    lstates[way].lru_position = 0;

    // --- Reuse counter update ---
    if (hit)
        lstates[way].reuse_counter++;
    else
        lstates[way].reuse_counter = 0;

    // --- Spatial reuse detection ---
    bool spatial = false;
    if (!sstate.addr_history.empty()) {
        uint64_t last_addr = sstate.addr_history.back();
        if (std::abs((int64_t)paddr - (int64_t)last_addr) <= SPATIAL_ALIGNMENT)
            spatial = true;
    }
    lstates[way].spatial_reuse = spatial;

    // --- Address history for stride detection ---
    if (sstate.addr_history.size() >= STRIDE_HISTORY_LEN)
        sstate.addr_history.erase(sstate.addr_history.begin());
    sstate.addr_history.push_back(paddr);
    sstate.stride = detect_stride(sstate.addr_history);

    // --- Reuse history for phase detection ---
    if (sstate.reuse_history.size() >= REUSE_HISTORY_LEN)
        sstate.reuse_history.erase(sstate.reuse_history.begin());
    sstate.reuse_history.push_back(hit ? 1 : 0);

    lstates[way].tag = paddr;
    lstates[way].valid = 1;
}

void PrintStats() {
    std::cout << "DRSTAR: Total evictions: " << total_evictions << std::endl;
    std::cout << "DRSTAR: Regular phase evictions: " << regular_evictions << std::endl;
    std::cout << "DRSTAR: Irregular phase evictions: " << irregular_evictions << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "DRSTAR heartbeat: evictions=" << total_evictions
              << " regular=" << regular_evictions
              << " irregular=" << irregular_evictions << std::endl;
}