#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Metadata for each cache block
struct BlockMetadata {
    uint64_t last_access_cycle; // Recency tracking
    uint32_t access_count;      // Frequency tracking
};

std::vector<std::vector<BlockMetadata>> metadata(LLC_SETS, std::vector<BlockMetadata>(LLC_WAYS));

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            metadata[set][way] = {0, 0};
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
    uint32_t victim_way = 0;
    uint64_t oldest_cycle = UINT64_MAX;
    uint32_t lowest_access_count = UINT32_MAX;

    // Phase-aware victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        const auto &block_meta = metadata[set][way];

        // Prefer blocks with low access frequency for irregular workloads
        if (block_meta.access_count < lowest_access_count) {
            victim_way = way;
            lowest_access_count = block_meta.access_count;
            oldest_cycle = block_meta.last_access_cycle;
        }
        // Break ties using recency (oldest cycle)
        else if (block_meta.access_count == lowest_access_count && block_meta.last_access_cycle < oldest_cycle) {
            victim_way = way;
            oldest_cycle = block_meta.last_access_cycle;
        }
    }

    return victim_way;
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
    uint64_t current_cycle = champsim::current_cycle;

    if (hit) {
        // Update metadata for hits
        metadata[set][way].last_access_cycle = current_cycle;
        metadata[set][way].access_count++;
    } else {
        // Reset metadata for new blocks
        metadata[set][way] = {current_cycle, 1};
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "APARP: End-of-simulation statistics." << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "APARP: Heartbeat statistics." << std::endl;
}