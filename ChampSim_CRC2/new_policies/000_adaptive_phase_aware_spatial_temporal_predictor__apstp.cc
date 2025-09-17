#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <array>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Tunable parameters
constexpr int PHASE_WINDOW = 64;           // Number of accesses to observe before phase update
constexpr int PHASE_ENTROPY_THRESHOLD = 10; // Entropy threshold to detect irregular phase
constexpr int PC_REUSE_TABLE_SIZE = 8192;  // Number of entries in PC reuse table
constexpr int SPATIAL_CLUSTER_RADIUS = 4;  // Number of neighbor blocks to consider for spatial locality

// Replacement state structures
struct LineMeta {
    uint64_t last_access;   // Timestamp of last access (for LRU)
    uint32_t reuse_score;   // PC-based reuse score
    uint32_t spatial_score; // Spatial locality score
};

struct SetPhaseState {
    uint32_t access_count;
    uint32_t unique_addr_count;
    std::unordered_map<uint64_t, uint32_t> addr_hist;
    bool is_irregular_phase; // true: pointer-chasing/irregular, false: regular/stencil
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetPhaseState, LLC_SETS> set_phase_state;
uint64_t global_timestamp = 0;

// PC-based reuse predictor
struct PCEntry {
    uint32_t reuse_counter;
    uint32_t last_used;
};
std::unordered_map<uint64_t, PCEntry> pc_reuse_table;

// Telemetry
uint64_t total_hits = 0, total_misses = 0;
uint64_t phase_switches = 0;

// Initialize replacement state
void InitReplacementState() {
    for (auto& set : line_meta)
        for (auto& meta : set)
            meta = {0, 0, 0};
    for (auto& phase : set_phase_state) {
        phase.access_count = 0;
        phase.unique_addr_count = 0;
        phase.addr_hist.clear();
        phase.is_irregular_phase = false;
    }
    pc_reuse_table.clear();
    global_timestamp = 0;
    total_hits = total_misses = phase_switches = 0;
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
    global_timestamp++;

    // --- Phase detection ---
    auto& phase = set_phase_state[set];
    phase.access_count++;
    phase.addr_hist[paddr]++;
    if (phase.access_count == PHASE_WINDOW) {
        phase.unique_addr_count = phase.addr_hist.size();
        // Simple entropy: count unique addresses in window
        if (phase.unique_addr_count > PHASE_ENTROPY_THRESHOLD) {
            if (!phase.is_irregular_phase) phase_switches++;
            phase.is_irregular_phase = true; // pointer-chasing/irregular
        } else {
            if (phase.is_irregular_phase) phase_switches++;
            phase.is_irregular_phase = false; // stencil/regular
        }
        phase.access_count = 0;
        phase.addr_hist.clear();
    }

    // --- PC reuse score ---
    uint32_t pc_reuse_score = 0;
    auto pc_it = pc_reuse_table.find(PC);
    if (pc_it != pc_reuse_table.end())
        pc_reuse_score = pc_it->second.reuse_counter;

    // --- Spatial score ---
    uint32_t spatial_score[LLC_WAYS] = {0};
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        spatial_score[w] = 0;
        uint64_t line_addr = current_set[w].address;
        // Check spatial cluster
        for (uint32_t k = 1; k <= SPATIAL_CLUSTER_RADIUS; ++k) {
            for (uint32_t w2 = 0; w2 < LLC_WAYS; ++w2) {
                if (w2 == w) continue;
                uint64_t neighbor_addr = current_set[w2].address;
                if (neighbor_addr == 0) continue;
                if (std::abs((int64_t)neighbor_addr - (int64_t)line_addr) <= k * 64) // 64B block
                    spatial_score[w]++;
            }
        }
    }

    // --- Victim selection ---
    uint32_t victim = 0;
    if (phase.is_irregular_phase) {
        // Pointer-chasing: prefer evicting lowest PC reuse score, then oldest
        uint32_t min_score = UINT32_MAX;
        uint64_t oldest = UINT64_MAX;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            uint32_t score = line_meta[set][w].reuse_score;
            if (score < min_score || (score == min_score && line_meta[set][w].last_access < oldest)) {
                min_score = score;
                oldest = line_meta[set][w].last_access;
                victim = w;
            }
        }
    } else {
        // Regular/stencil: prefer evicting lines with lowest spatial score, then oldest
        uint32_t min_spatial = UINT32_MAX;
        uint64_t oldest = UINT64_MAX;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (spatial_score[w] < min_spatial ||
                (spatial_score[w] == min_spatial && line_meta[set][w].last_access < oldest)) {
                min_spatial = spatial_score[w];
                oldest = line_meta[set][w].last_access;
                victim = w;
            }
        }
    }
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
    global_timestamp++;
    auto& meta = line_meta[set][way];
    meta.last_access = global_timestamp;

    // Update PC reuse predictor
    auto& entry = pc_reuse_table[PC];
    if (hit) {
        entry.reuse_counter = std::min(entry.reuse_counter + 1, 255u);
        total_hits++;
    } else {
        entry.reuse_counter = std::max(entry.reuse_counter, 1u);
        total_misses++;
    }
    entry.last_used = global_timestamp;
    if (pc_reuse_table.size() > PC_REUSE_TABLE_SIZE) {
        // Simple LRU eviction for PC table
        uint64_t oldest = UINT64_MAX;
        uint64_t oldest_pc = 0;
        for (const auto& kv : pc_reuse_table) {
            if (kv.second.last_used < oldest) {
                oldest = kv.second.last_used;
                oldest_pc = kv.first;
            }
        }
        pc_reuse_table.erase(oldest_pc);
    }

    // Update line reuse score for victim
    meta.reuse_score = entry.reuse_counter;

    // Update spatial score for this line (count neighbors in set)
    meta.spatial_score = 0;
    for (uint32_t w2 = 0; w2 < LLC_WAYS; ++w2) {
        if (w2 == way) continue;
        uint64_t neighbor_addr = line_meta[set][w2].last_access;
        if (neighbor_addr == 0) continue;
        if (std::abs((int64_t)paddr - (int64_t)neighbor_addr) <= SPATIAL_CLUSTER_RADIUS * 64)
            meta.spatial_score++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "APSTP Policy: Total Hits = " << total_hits
              << ", Total Misses = " << total_misses
              << ", Phase Switches = " << phase_switches << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * total_hits / (total_hits + total_misses)) << "%" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[APSTP Heartbeat] Hits: " << total_hits
              << ", Misses: " << total_misses
              << ", Phase Switches: " << phase_switches << std::endl;
}