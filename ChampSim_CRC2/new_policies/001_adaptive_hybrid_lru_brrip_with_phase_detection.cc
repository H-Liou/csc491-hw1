#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRIP_MAX 3
#define RRIP_LONG 2 // Inserted with this value for BRRIP
#define RRIP_SHORT 0 // Inserted with this value for LRU-like

// Phase detection window
#define PHASE_WINDOW 128
#define PHASE_HIT_THRESHOLD 0.5

struct SetStats {
    uint32_t hits;
    uint32_t accesses;
    bool prefer_lru; // true: LRU, false: BRRIP
};

std::vector<std::vector<uint8_t>> rrip_state; // [set][way]
std::vector<SetStats> set_stats; // [set]

// Initialize replacement state
void InitReplacementState() {
    rrip_state.resize(LLC_SETS, std::vector<uint8_t>(LLC_WAYS, RRIP_MAX));
    set_stats.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        set_stats[set] = {0, 0, true}; // start with LRU preference
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
    // Use RRIP victim selection
    while (true) {
        // Look for block with RRIP_MAX
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrip_state[set][way] == RRIP_MAX) {
                return way;
            }
        }
        // If none found, increment all RRIP counters
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrip_state[set][way] < RRIP_MAX)
                rrip_state[set][way]++;
        }
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
    // Update phase stats
    set_stats[set].accesses++;
    if (hit)
        set_stats[set].hits++;

    // Phase detection every PHASE_WINDOW accesses
    if (set_stats[set].accesses % PHASE_WINDOW == 0) {
        double hit_rate = (double)set_stats[set].hits / set_stats[set].accesses;
        // If hit rate is high, prefer LRU; else prefer BRRIP
        set_stats[set].prefer_lru = (hit_rate > PHASE_HIT_THRESHOLD);
        set_stats[set].hits = 0;
        set_stats[set].accesses = 0;
    }

    // On hit: promote block (set RRIP to RRIP_SHORT)
    if (hit) {
        rrip_state[set][way] = RRIP_SHORT;
        return;
    }

    // On fill: insert with policy-dependent RRIP value
    if (set_stats[set].prefer_lru) {
        // LRU-like: insert with RRIP_SHORT (most recently used)
        rrip_state[set][way] = RRIP_SHORT;
    } else {
        // BRRIP: insert with RRIP_LONG (less likely to be reused soon)
        // Bimodal: 1/32 chance to insert as RRIP_SHORT
        if ((rand() % 32) == 0)
            rrip_state[set][way] = RRIP_SHORT;
        else
            rrip_state[set][way] = RRIP_LONG;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Adaptive Hybrid LRU-BRRIP Policy Stats\n";
    // Optionally print phase preference distribution
    uint32_t lru_sets = 0, brrip_sets = 0;
    for (auto &stat : set_stats) {
        if (stat.prefer_lru) lru_sets++;
        else brrip_sets++;
    }
    std::cout << "LRU sets: " << lru_sets << " BRRIP sets: " << brrip_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Can be left empty or print stats periodically
}