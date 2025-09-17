#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <array>
#include <algorithm>
#include <string.h>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Configurable parameters
constexpr int PHASE_WINDOW = 32;
constexpr int MAX_PHASES = 3;
constexpr int REUSE_HISTORY_DEPTH = 8;
constexpr int STRIDE_HISTORY_DEPTH = 8;
constexpr int PHASE_SWITCH_THRESHOLD = 6; // switches if new "phase" detected this many times in a window

struct SetTelemetry {
    // Keep short history of PCs and addresses for stride/reuse analysis
    std::array<uint64_t, REUSE_HISTORY_DEPTH> addr_history;
    std::array<uint64_t, STRIDE_HISTORY_DEPTH> stride_history;
    std::array<uint64_t, REUSE_HISTORY_DEPTH> pc_history;
    int history_ptr = 0;
    int stride_ptr = 0;

    // Stats for phase classification
    int recent_hits = 0;
    int recent_misses = 0;
    uint64_t prev_addr = 0;
    uint64_t prev_pc = 0;

    int phase_mode = 0; // 0: LRU, 1: Belady/learned, 2: Bypass/spatial
    int phase_switch_count = 0;
    int lru_states[LLC_WAYS] = {0}; // Per-way state for LRU
    std::array<int, LLC_WAYS> belady_prediction = {0};

    void reset_stats() {
        recent_hits = recent_misses = phase_switch_count = 0;
        history_ptr = stride_ptr = 0;
        std::fill(addr_history.begin(), addr_history.end(), 0);
        std::fill(stride_history.begin(), stride_history.end(), 0);
        std::fill(pc_history.begin(), pc_history.end(), 0);
    }
};

std::array<SetTelemetry, LLC_SETS> set_telemetry;

void update_history(SetTelemetry& tel, uint64_t addr, uint64_t pc)
{
    tel.addr_history[tel.history_ptr] = addr;
    tel.pc_history[tel.history_ptr] = pc;
    if (tel.history_ptr > 0) {
        tel.stride_history[tel.stride_ptr] = addr - tel.addr_history[(tel.history_ptr - 1) % REUSE_HISTORY_DEPTH];
        tel.stride_ptr = (tel.stride_ptr + 1) % STRIDE_HISTORY_DEPTH;
    }
    tel.history_ptr = (tel.history_ptr + 1) % REUSE_HISTORY_DEPTH;
}

int detect_phase(const SetTelemetry& tel)
{
    // Detect regular stride (LBM-like, spatial phase)
    int spatial_cnt = 0;
    int irregular_cnt = 0;
    int pointer_chase_cnt = 0;

    // Check stride regularity
    for (int i = 1; i < STRIDE_HISTORY_DEPTH; ++i) {
        if (tel.stride_history[i] == tel.stride_history[i - 1] && tel.stride_history[i] != 0)
            spatial_cnt++;
        else if ((tel.stride_history[i] > (1ULL << 12)) && (tel.stride_history[i - 1] > (1ULL << 12)))
            pointer_chase_cnt++;
        else
            irregular_cnt++;
    }

    // PC diversity (high = irregular control flow / omnetpp/mcf/astar)
    std::unordered_map<uint64_t, int> pc_counts;
    for (int i = 0; i < REUSE_HISTORY_DEPTH; ++i)
        pc_counts[tel.pc_history[i]]++;

    int unique_pcs = pc_counts.size();

    // Simple thresholds to classify phase
    if (spatial_cnt > STRIDE_HISTORY_DEPTH / 2) // spatial locality
        return 2; // spatial
    else if (unique_pcs > REUSE_HISTORY_DEPTH / 2) // high diversity, irregular
        return 1; // learned/Belady
    else // moderate reuse, stable PC
        return 0; // LRU

    // Fallback: Use miss/hit ratio as tie-breaker
}

void switch_phase(SetTelemetry& tel)
{
    int new_mode = detect_phase(tel);
    if (new_mode != tel.phase_mode) {
        tel.phase_switch_count++;
        if (tel.phase_switch_count >= PHASE_SWITCH_THRESHOLD) {
            tel.phase_mode = new_mode;
            tel.phase_switch_count = 0;
        }
    } else {
        tel.phase_switch_count = 0; // reset if not changing
    }
}

void InitReplacementState() {
    for (auto& tel : set_telemetry)
        tel.reset_stats();
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetTelemetry& tel = set_telemetry[set];
    switch_phase(tel);

    // LRU Mode: Evict least recently used
    if (tel.phase_mode == 0) {
        int lru_way = 0, lru_state = tel.lru_states[0];
        for (int way = 1; way < LLC_WAYS; ++way) {
            if (tel.lru_states[way] < lru_state) {
                lru_state = tel.lru_states[way];
                lru_way = way;
            }
        }
        return lru_way;
    }
    // Learned/Belady-like Mode: Evict line predicted to be last used
    else if (tel.phase_mode == 1) {
        // If possible, evict way with lowest prediction (bad reuse)
        int victim = 0, pred = tel.belady_prediction[0];
        for (int way = 1; way < LLC_WAYS; ++way) {
            if (tel.belady_prediction[way] < pred) {
                pred = tel.belady_prediction[way];
                victim = way;
            }
        }
        return victim;
    }
    // Spatial/Bypass Mode: Evict line farthest in stride or low temporal
    else {
        // Choose line not used in current stride window (poor temporal)
        std::vector<int> candidates;
        for (int way = 0; way < LLC_WAYS; ++way) {
            uint64_t addr = current_set[way].address;
            bool found = false;
            for (int i = 0; i < STRIDE_HISTORY_DEPTH; ++i) {
                if (tel.addr_history[i] == addr)
                    found = true;
            }
            if (!found)
                candidates.push_back(way);
        }
        if (!candidates.empty())
            return candidates[0];
        // Fallback: Random (to avoid thrashing if stuck in phase)
        return rand() % LLC_WAYS;
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
    SetTelemetry& tel = set_telemetry[set];
    update_history(tel, paddr, PC);

    // Update LRU state counters
    if (tel.phase_mode == 0) {
        // Move "touched" way to MRU
        int max_lru = *std::max_element(tel.lru_states, tel.lru_states + LLC_WAYS);
        tel.lru_states[way] = max_lru + 1;
    }

    // Update predictor/belady scoring
    else if (tel.phase_mode == 1) {
        // Easy reuse score: increment on hit, decay on miss
        if (hit)
            tel.belady_prediction[way] += 2;
        else
            tel.belady_prediction[way] = std::max(0, tel.belady_prediction[way] - 1);
        // Slightly boost lines in stride window
        for (int i = 0; i < STRIDE_HISTORY_DEPTH; ++i) {
            if (tel.addr_history[i] == paddr)
                tel.belady_prediction[way]++;
        }
    }

    // Bypass/spatial mode: only cache blocks with spatial locality
    else if (tel.phase_mode == 2) {
        // If victim_addr is not in stride history, mark as quick evict
        bool found = false;
        for (int i = 0; i < STRIDE_HISTORY_DEPTH; ++i) {
            if (tel.addr_history[i] == victim_addr)
                found = true;
        }
        tel.belady_prediction[way] = (found ? 2 : 0);
    }

    // Track recent hit/miss stats for telemetry
    if (hit)
        tel.recent_hits++;
    else
        tel.recent_misses++;
}

uint64_t apah_total_phase_switches = 0;
uint64_t apah_hit[LLC_SETS] = {0};
uint64_t apah_miss[LLC_SETS] = {0};

void PrintStats() {
    int mode_counts[MAX_PHASES] = {0};
    int switches = 0;
    int total_hits = 0, total_misses = 0;
    for (int set = 0; set < LLC_SETS; ++set) {
        mode_counts[set_telemetry[set].phase_mode]++;
        switches += set_telemetry[set].phase_switch_count;
        total_hits += set_telemetry[set].recent_hits;
        total_misses += set_telemetry[set].recent_misses;
    }
    std::cout << "APAH Final Stats:\n";
    std::cout << "Phase Mode Counts (LRU, Belady, Spatial): " << mode_counts[0]
              << " " << mode_counts[1] << " " << mode_counts[2] << "\n";
    std::cout << "Total Phase Switches: " << switches << "\n";
    std::cout << "Total Hits: " << total_hits << " Total Misses: " << total_misses << "\n";
    double hit_rate = double(total_hits) / (total_hits + total_misses) * 100.0;
    std::cout << "Hit Rate: " << hit_rate << "%\n";
}

void PrintStats_Heartbeat() {
    // Print phase breakdown and hit rate every heartbeat (can be hooked to simulation ticks)
    int mode_counts[MAX_PHASES] = {0};
    int total_hits = 0, total_misses = 0;
    for (int set = 0; set < LLC_SETS; ++set) {
        mode_counts[set_telemetry[set].phase_mode]++;
        total_hits += set_telemetry[set].recent_hits;
        total_misses += set_telemetry[set].recent_misses;
    }
    std::cout << "[Heartbeat] APAH Phases: LRU=" << mode_counts[0]
              << " Belady=" << mode_counts[1] << " Spatial=" << mode_counts[2] << "\n";
    double hit_rate = double(total_hits) / (total_hits + total_misses) * 100.0;
    std::cout << "[Heartbeat] APAH Hit Rate: " << hit_rate << "%\n";
}