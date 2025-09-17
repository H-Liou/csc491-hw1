#include <vector>
#include <cstdint>
#include <iostream>
#include <cmath>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Replacement state structures
struct LineState {
    uint64_t last_access;  // Tracks recency
    uint64_t frequency;    // Tracks frequency
    uint64_t spatial_score; // Tracks spatial locality
    uint64_t temporal_score; // Tracks temporal locality
    uint64_t phase_tag;    // Tracks phase information
};

std::vector<std::vector<LineState>> replacement_state(LLC_SETS, std::vector<LineState>(LLC_WAYS));

// Global counters for phase detection and decay
uint64_t global_access_counter = 0;
uint64_t phase_interval = 100000; // Interval to detect phase changes
uint64_t current_phase = 0;
double decay_factor = 0.9; // Decay factor for scores

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            replacement_state[set][way] = {0, 0, 0, 0, 0};
        }
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
    uint32_t victim = 0;
    double min_score = std::numeric_limits<double>::max();

    // Calculate scores based on recency, frequency, spatial locality, temporal locality, and phase alignment
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        uint64_t recency_score = global_access_counter - replacement_state[set][way].last_access;
        uint64_t frequency_score = replacement_state[set][way].frequency;
        uint64_t spatial_score = replacement_state[set][way].spatial_score;
        uint64_t temporal_score = replacement_state[set][way].temporal_score;
        uint64_t phase_mismatch = (replacement_state[set][way].phase_tag != current_phase) ? 1 : 0;

        // Predictive weighting: prioritize spatial or temporal based on recent access patterns
        double weighted_score = recency_score +
                                (frequency_score * 1.5) +
                                (spatial_score * 2.0) +
                                (temporal_score * 1.8) +
                                (phase_mismatch * 1000);

        if (weighted_score < min_score) {
            min_score = weighted_score;
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
    global_access_counter++;

    if (hit) {
        // Update recency, frequency, and locality scores on hit
        replacement_state[set][way].last_access = global_access_counter;
        replacement_state[set][way].frequency++;
        replacement_state[set][way].spatial_score += 1; // Increment spatial score for reuse
        replacement_state[set][way].temporal_score += 1; // Increment temporal score for reuse
    } else {
        // Reset state for the new block on miss
        replacement_state[set][way].last_access = global_access_counter;
        replacement_state[set][way].frequency = 1;
        replacement_state[set][way].spatial_score = 0; // Reset spatial score
        replacement_state[set][way].temporal_score = 0; // Reset temporal score
        replacement_state[set][way].phase_tag = current_phase;
    }

    // Apply decay to frequency and locality scores periodically
    if (global_access_counter % 1000 == 0) {
        for (uint32_t i = 0; i < LLC_SETS; ++i) {
            for (uint32_t j = 0; j < LLC_WAYS; ++j) {
                replacement_state[i][j].frequency *= decay_factor;
                replacement_state[i][j].spatial_score *= decay_factor;
                replacement_state[i][j].temporal_score *= decay_factor;
            }
        }
    }

    // Detect phase changes periodically
    if (global_access_counter % phase_interval == 0) {
        current_phase++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Simulation complete. Final phase: " << current_phase << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "Heartbeat: Global access counter = " << global_access_counter
              << ", Current phase = " << current_phase << std::endl;
}