#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block approximation: 2-bit counter per block ---
uint8_t dead_counter[LLC_SETS][LLC_WAYS];

// --- Decay counter: per set, 8-bit ---
uint8_t decay_counter[LLC_SETS];

// --- Parameters ---
#define DEAD_THRESHOLD 3      // Counter value indicating a dead block
#define DECAY_EPOCH 256       // How often to decay dead counters

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;            // Start at SRRIP mid value
            dead_counter[set][way] = 0;    // Dead counters zero
        }
        decay_counter[set] = 0;
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
    // Standard SRRIP victim selection (evict block with RRPV==3)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
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
    // --- Dead-block update ---
    if (hit) {
        // On hit, promote to MRU and reset dead-counter
        rrpv[set][way] = 0;
        dead_counter[set][way] = 0;
    } else {
        // On miss/insert, increment dead-counter for victim line
        if (dead_counter[set][way] < 3)
            dead_counter[set][way]++;
        // Insert new block:
        // If victim was dead (counter high), insert at LRU (RRPV=3) to minimize pollution
        // Else, use SRRIP default (mid RRPV=2)
        if (dead_counter[set][way] >= DEAD_THRESHOLD)
            rrpv[set][way] = 3; // dead block, minimize residency
        else
            rrpv[set][way] = 2; // neutral, allow retention
        // Reset dead-counter for new block
        dead_counter[set][way] = 0;
    }

    // --- Periodically decay dead counters for this set ---
    decay_counter[set]++;
    if (decay_counter[set] >= DECAY_EPOCH) {
        decay_counter[set] = 0;
        // Decay: halve all dead counters
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            dead_counter[set][w] >>= 1;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_lines = 0;
    int live_lines = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_counter[set][way] >= DEAD_THRESHOLD) dead_lines++;
            else live_lines++;
    std::cout << "SRRIP-DBI: Dead lines: " << dead_lines
              << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "SRRIP-DBI: Live lines: " << live_lines << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_lines = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_counter[set][way] >= DEAD_THRESHOLD) dead_lines++;
    std::cout << "SRRIP-DBI: Dead lines: " << dead_lines << std::endl;
}