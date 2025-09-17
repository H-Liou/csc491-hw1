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
    uint64_t last_access; // Tracks recency
    uint64_t frequency;   // Tracks frequency
    uint64_t phase_tag;   // Tracks phase information
};

std::vector<std::vector<LineState>> replacement_state(LLC_SETS, std::vector<LineState>(LLC_WAYS));

// Global counters for phase detection
uint64_t global_access_counter = 0;
uint64_t phase_interval = 100000; // Interval to detect phase changes
uint64_t current_phase = 0;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            replacement_state[set][way] = {0, 0, 0};
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
    uint64_t min_score = UINT64_MAX;

    // Calculate scores based on recency, frequency, and phase alignment
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        uint64_t recency_score = global_access_counter - replacement_state[set][way].last_access;
        uint64_t frequency_score = replacement_state[set][way].frequency;
        uint64_t phase_mismatch = (replacement_state[set][way].phase_tag != current_phase) ? 1 : 0;

        // Weighted score: prioritize recency and penalize phase mismatch
        uint64_t score = recency_score + (frequency_score * 2) + (phase_mismatch * 1000);

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
    global_access_counter++;

    if (hit) {
        // Update recency and frequency on hit
        replacement_state[set][way].last_access = global_access_counter;
        replacement_state[set][way].frequency++;
    } else {
        // Reset state for the new block on miss
        replacement_state[set][way].last_access = global_access_counter;
        replacement_state[set][way].frequency = 1;
        replacement_state[set][way].phase_tag = current_phase;
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