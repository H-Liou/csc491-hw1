#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include <cmath>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Tunable Parameters ---
constexpr int PHASE_WINDOW = 2048;         // Number of accesses to consider for phase detection
constexpr int PHASE_ENTROPY_THRESHOLD = 10; // Entropy threshold for phase change
constexpr int SIGNATURE_BITS = 12;         // Bits for PC-based signature
constexpr int MAX_REUSE_COUNTER = 7;       // Max value for reuse predictor
constexpr int SPATIAL_WINDOW = 4;          // Number of neighboring blocks for spatial locality

// --- Replacement State ---
struct PASR_Line {
    uint16_t signature; // PC signature
    uint8_t reuse_counter; // Temporal reuse predictor
    uint8_t spatial_counter; // Spatial locality predictor
    uint32_t last_access; // Timestamp for recency
};

std::vector<std::vector<PASR_Line>> pasr_state(LLC_SETS, std::vector<PASR_Line>(LLC_WAYS));
std::vector<uint64_t> pasr_timestamps(LLC_SETS, 0);

// --- Phase Detection State ---
struct PhaseState {
    std::unordered_map<uint16_t, int> pc_histogram;
    int access_count = 0;
    double last_entropy = 0.0;
    bool phase_changed = false;
} phase_state;

// --- Helper Functions ---
inline uint16_t get_signature(uint64_t PC) {
    return (PC >> 2) & ((1 << SIGNATURE_BITS) - 1);
}

double compute_entropy(const std::unordered_map<uint16_t, int>& hist, int total) {
    double entropy = 0.0;
    for (const auto& kv : hist) {
        double p = (double)kv.second / total;
        if (p > 0.0) entropy -= p * std::log2(p);
    }
    return entropy;
}

void detect_phase(uint64_t PC) {
    uint16_t sig = get_signature(PC);
    phase_state.pc_histogram[sig]++;
    phase_state.access_count++;

    if (phase_state.access_count >= PHASE_WINDOW) {
        double entropy = compute_entropy(phase_state.pc_histogram, phase_state.access_count);
        phase_state.phase_changed = std::abs(entropy - phase_state.last_entropy) > PHASE_ENTROPY_THRESHOLD;
        phase_state.last_entropy = entropy;
        phase_state.pc_histogram.clear();
        phase_state.access_count = 0;
    } else {
        phase_state.phase_changed = false;
    }
}

// --- API Functions ---
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            pasr_state[set][way] = {0, 0, 0, 0};
        }
        pasr_timestamps[set] = 0;
    }
    phase_state.pc_histogram.clear();
    phase_state.access_count = 0;
    phase_state.last_entropy = 0.0;
    phase_state.phase_changed = false;
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
    // Phase detection on every access
    detect_phase(PC);

    // Score each way: lower score = better candidate for eviction
    uint32_t victim = 0;
    int min_score = INT32_MAX;
    uint16_t curr_sig = get_signature(PC);

    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        PASR_Line& line = pasr_state[set][way];

        // If line is invalid, prefer eviction
        if (!current_set[way].valid) return way;

        // Score calculation:
        // - High reuse_counter = less likely to evict
        // - High spatial_counter = less likely to evict
        // - Older last_access = more likely to evict
        // - If phase changed, penalize lines with old signature (to flush pollution)
        int score = 0;
        score += (MAX_REUSE_COUNTER - line.reuse_counter) * 4;
        score += (SPATIAL_WINDOW - line.spatial_counter) * 2;
        score += (pasr_timestamps[set] - line.last_access) / 64; // recency (coarse)
        if (phase_state.phase_changed && line.signature != curr_sig)
            score += 16; // penalize lines from previous phase

        if (score < min_score) {
            min_score = score;
            victim = way;
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
    PASR_Line& line = pasr_state[set][way];
    uint16_t sig = get_signature(PC);

    // On hit: boost reuse, update spatial, recency
    if (hit) {
        line.reuse_counter = std::min(line.reuse_counter + 1, (uint8_t)MAX_REUSE_COUNTER);
        line.spatial_counter = std::min(line.spatial_counter + 1, (uint8_t)SPATIAL_WINDOW);
    } else {
        // On miss: reset reuse, spatial locality
        line.reuse_counter = 1;
        line.spatial_counter = 1;
    }
    line.signature = sig;
    line.last_access = ++pasr_timestamps[set];

    // Spatial locality: check if neighboring blocks in set were accessed recently
    for (int offset = -SPATIAL_WINDOW/2; offset <= SPATIAL_WINDOW/2; ++offset) {
        if (offset == 0) continue;
        int neighbor = (int)way + offset;
        if (neighbor >= 0 && neighbor < LLC_WAYS) {
            PASR_Line& nline = pasr_state[set][neighbor];
            if (std::abs((int)line.last_access - (int)nline.last_access) < 16)
                line.spatial_counter = std::min(line.spatial_counter + 1, (uint8_t)SPATIAL_WINDOW);
        }
    }

    // If phase changed, decay reuse/spatial counters to adapt quickly
    if (phase_state.phase_changed) {
        line.reuse_counter = std::max(line.reuse_counter / 2, (uint8_t)1);
        line.spatial_counter = std::max(line.spatial_counter / 2, (uint8_t)1);
    }
}

// --- Telemetry & Statistics ---
uint64_t pasr_total_hits = 0, pasr_total_misses = 0, pasr_phase_changes = 0;

void PrintStats() {
    std::cout << "PASR: Total Hits: " << pasr_total_hits
              << " Total Misses: " << pasr_total_misses
              << " Phase Changes: " << pasr_phase_changes << std::endl;
}

void PrintStats_Heartbeat() {
    if (phase_state.phase_changed)
        pasr_phase_changes++;
    std::cout << "[PASR Heartbeat] Hits: " << pasr_total_hits
              << " Misses: " << pasr_total_misses
              << " Phase Changes: " << pasr_phase_changes << std::endl;
}

// --- Hook for hit/miss accounting (call in simulator) ---
void PASR_AccountHitMiss(uint8_t hit) {
    if (hit) pasr_total_hits++;
    else pasr_total_misses++;
}