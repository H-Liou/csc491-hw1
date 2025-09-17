#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <unordered_set>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP parameters ---
constexpr uint8_t RRIP_BITS = 2;          // 2 bits per line: values 0 (long re-use) to 3 (evict soon)
constexpr uint8_t RRIP_MAX = (1 << RRIP_BITS) - 1; // 3
constexpr uint8_t RRIP_INSERT_SPATIAL = 1;         // Insert lines with value 1 for spatial sets
constexpr uint8_t RRIP_INSERT_IRREGULAR = 3;       // Insert lines with value 3 for irregular sets

// --- Segmentation parameters ---
constexpr int SEG_WINDOW = 64;             // Window for segment adaptation
constexpr double SPATIAL_THRESHOLD = 0.60; // If >60% accesses are to neighbor blocks, set is "spatial"

// --- Frequency Filter parameters ---
constexpr int FREQ_FILTER_SIZE = 8;        // Tracks last 8 block signatures per set

struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
};

struct SetStats {
    uint32_t accesses;
    uint32_t spatial_hits;
    bool is_spatial;
    std::vector<uint64_t> freq_filter; // FIFO of block signatures
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetStats, LLC_SETS> set_stats;
uint64_t global_hits = 0, global_misses = 0;

// Helper: check if block signature is in freq filter
bool freq_filter_contains(const std::vector<uint64_t>& filter, uint64_t sig) {
    for (auto& s : filter)
        if (s == sig) return true;
    return false;
}

// Helper: add block signature to freq filter (FIFO)
void freq_filter_add(std::vector<uint64_t>& filter, uint64_t sig) {
    auto it = std::find(filter.begin(), filter.end(), sig);
    if (it != filter.end()) return; // already present
    if (filter.size() >= FREQ_FILTER_SIZE)
        filter.erase(filter.begin());
    filter.push_back(sig);
}

// Initialize replacement state
void InitReplacementState() {
    for (auto& set : line_meta)
        for (auto& line : set)
            line = {0, RRIP_MAX}; // All lines start as "evict soon"
    for (auto& stats : set_stats) {
        stats = {0, 0, true, std::vector<uint64_t>()};
    }
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
    auto& stats = set_stats[set];
    stats.accesses++;

    uint64_t block_sig = paddr >> 6; // block-aligned address

    // Check for spatial access: is this access to a neighbor block?
    bool spatial_access = false;
    if (!stats.freq_filter.empty()) {
        for (auto& s : stats.freq_filter) {
            if (block_sig == s + 1 || block_sig == s - 1) {
                spatial_access = true;
                break;
            }
        }
    }
    if (spatial_access)
        stats.spatial_hits++;

    // Every SEG_WINDOW accesses, update segment type
    if (stats.accesses % SEG_WINDOW == 0) {
        double spatial_rate = static_cast<double>(stats.spatial_hits) / stats.accesses;
        stats.is_spatial = (spatial_rate > SPATIAL_THRESHOLD);
        // Reset window
        stats.accesses = 0;
        stats.spatial_hits = 0;
    }

    // Frequency filter maintenance
    freq_filter_add(stats.freq_filter, block_sig);

    if (hit) {
        global_hits++;
        // Promote: If block is frequent, RRIP=0; else RRIP=1
        if (freq_filter_contains(stats.freq_filter, block_sig))
            line_meta[set][way].rrip = 0;
        else
            line_meta[set][way].rrip = 1;
        line_meta[set][way].tag = block_sig;
        return;
    } else {
        global_misses++;
    }

    // Miss: Insert block
    uint8_t insert_rrip;
    if (stats.is_spatial) {
        // For spatial sets, retain longer if frequent
        if (freq_filter_contains(stats.freq_filter, block_sig))
            insert_rrip = 0;
        else
            insert_rrip = RRIP_INSERT_SPATIAL;
    } else {
        // For irregular sets, only retain frequent blocks
        if (freq_filter_contains(stats.freq_filter, block_sig))
            insert_rrip = 1;
        else
            insert_rrip = RRIP_INSERT_IRREGULAR;
    }

    line_meta[set][way].rrip = insert_rrip;
    line_meta[set][way].tag = block_sig;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SA-RRIP-FF Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[SA-RRIP-FF Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
}