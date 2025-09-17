#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP parameters ---
constexpr uint8_t RRIP_BITS = 2;          // 2 bits per line: values 0 (long re-use) to 3 (evict soon)
constexpr uint8_t RRIP_MAX = (1 << RRIP_BITS) - 1; // 3
constexpr uint8_t RRIP_INSERT = RRIP_MAX - 1;      // Insert lines with value 2

// --- Bypass parameters ---
constexpr int BYPASS_WINDOW = 128;        // Window for bypass stats
constexpr double BYPASS_MISS_THRESHOLD = 0.70; // If miss rate > 70%, enable bypass
constexpr double BYPASS_PROB = 0.50;     // Probability to bypass when enabled

struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
};

struct SetStats {
    uint32_t accesses;
    uint32_t misses;
    bool bypass_enabled;
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetStats, LLC_SETS> set_stats;
uint64_t global_hits = 0, global_misses = 0;

// Initialize replacement state
void InitReplacementState() {
    for (auto& set : line_meta)
        for (auto& line : set)
            line = {0, RRIP_MAX}; // All lines start as "evict soon"
    for (auto& stats : set_stats)
        stats = {0, 0, false};
    global_hits = global_misses = 0;
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
    // Standard RRIP victim selection: look for line with RRIP_MAX, else increment all and repeat
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (line_meta[set][w].rrip == RRIP_MAX)
                return w;
        }
        // No victim found, increment all RRIP values (aging)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (line_meta[set][w].rrip < RRIP_MAX)
                line_meta[set][w].rrip++;
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
    // Update stats
    auto& stats = set_stats[set];
    stats.accesses++;
    if (!hit) {
        stats.misses++;
        global_misses++;
    } else {
        global_hits++;
    }

    // Every BYPASS_WINDOW accesses, update bypass flag
    if (stats.accesses % BYPASS_WINDOW == 0) {
        double miss_rate = static_cast<double>(stats.misses) / stats.accesses;
        stats.bypass_enabled = (miss_rate > BYPASS_MISS_THRESHOLD);
        // Reset window
        stats.accesses = 0;
        stats.misses = 0;
    }

    // If hit: promote to RRIP=0 (long re-use)
    if (hit) {
        line_meta[set][way].rrip = 0;
        line_meta[set][way].tag = paddr >> 6;
        return;
    }

    // Miss: consider bypass
    bool bypass = false;
    if (stats.bypass_enabled) {
        // Simple hash for pseudo-random bypass
        uint64_t hash = (paddr ^ PC ^ global_hits ^ global_misses) & 0xFF;
        bypass = (hash < (BYPASS_PROB * 256));
    }

    if (bypass) {
        // Do not insert the new line (simulate as if the block is not cached)
        // No update to line_meta[set][way]
        return;
    }

    // Insert: set RRIP to RRIP_INSERT, update tag
    line_meta[set][way].rrip = RRIP_INSERT;
    line_meta[set][way].tag = paddr >> 6;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "A-RRIP-DB Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[A-RRIP-DB Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
}