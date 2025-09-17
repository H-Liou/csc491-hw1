#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE     1
#define LLC_SETS     (NUM_CORE * 2048)
#define LLC_WAYS     16

// RRIP parameters
static const uint8_t RRPV_MAX       = 3;     // 2‐bit RRPV [0..3]
static const uint8_t RRPV_INIT_S    = 2;     // SRRIP insertion (short RRPV)
static const uint8_t RRPV_INIT_B    = 3;     // BRRIP insertion (long RRPV)

// Set dueling parameters
static const uint32_t SAMPLE_DIST   = 64;    // stride between sample sets
static const uint32_t PSEL_BITS     = 10;
static const uint32_t PSEL_MAX      = (1 << PSEL_BITS) - 1;
static const uint32_t PSEL_INIT     = (PSEL_MAX + 1) / 2;

// Replacement state per line
struct BlockInfo {
    uint8_t rrpv;           // re‐reference prediction value
};

static BlockInfo ReplState[LLC_SETS][LLC_WAYS];

// Global policy selector
static uint32_t PSEL;

// Statistics
static uint64_t stat_hits   = 0;
static uint64_t stat_misses = 0;

// Helpers to identify leader sets
static inline bool is_srrip_leader(uint32_t set) {
    return (set % SAMPLE_DIST) == 0;
}
static inline bool is_br_rip_leader(uint32_t set) {
    return (set % SAMPLE_DIST) == 1;
}
// Follower sets use SRRIP when PSEL MSB=1, else BRRIP
static inline bool follower_uses_srrip() {
    return (PSEL >> (PSEL_BITS - 1)) & 1;
}

// Initialize replacement state
void InitReplacementState() {
    // Initialize all lines with max RRPV (cold)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            ReplState[s][w].rrpv = RRPV_MAX;
        }
    }
    // Initialize PSEL to neutral
    PSEL = PSEL_INIT;
    // Reset stats
    stat_hits   = 0;
    stat_misses = 0;
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
    // Search for line with RRPV == RRPV_MAX
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (ReplState[set][w].rrpv == RRPV_MAX) {
                return w;
            }
        }
        // No candidate yet; age all lines
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (ReplState[set][w].rrpv < RRPV_MAX) {
                ReplState[set][w].rrpv++;
            }
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
    if (hit) {
        stat_hits++;
        // Promote on hit
        ReplState[set][way].rrpv = 0;
    } else {
        stat_misses++;
        // Determine insertion policy
        bool use_srrip;
        if (is_srrip_leader(set)) {
            use_srrip = true;
        } else if (is_br_rip_leader(set)) {
            use_srrip = false;
        } else {
            use_srrip = follower_uses_srrip();
        }
        // Assign RRPV based on chosen policy
        ReplState[set][way].rrpv = use_srrip ? RRPV_INIT_S
                                              : RRPV_INIT_B;
        // Update PSEL on misses in leader sets
        if (is_srrip_leader(set)) {
            // BRRIP favored => decrement PSEL
            if (PSEL > 0) PSEL--;
        } else if (is_br_rip_leader(set)) {
            // SRRIP favored => increment PSEL
            if (PSEL < PSEL_MAX) PSEL++;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint64_t total = stat_hits + stat_misses;
    double hit_rate = total ? (100.0 * stat_hits / total) : 0.0;
    std::cout << "---- DRRIP Replacement Stats ----\n";
    std::cout << "Total Accesses: " << total << "\n";
    std::cout << "Hits: " << stat_hits
              << "  Misses: " << stat_misses
              << "  Hit Rate: " << hit_rate << "%\n";
    std::cout << "PSEL: " << PSEL << " [0.." << PSEL_MAX << "]\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}