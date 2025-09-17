#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr uint8_t RRIP_BITS = 2;
constexpr uint8_t RRIP_MAX = (1 << RRIP_BITS) - 1; // 3
constexpr uint8_t RRIP_INSERT_SPATIAL = 0;         // spatial: most likely to reuse
constexpr uint8_t RRIP_INSERT_TEMPORAL = 1;        // temporal: moderate reuse
constexpr uint8_t RRIP_INSERT_IRREGULAR = RRIP_MAX;// irregular: unlikely to reuse

constexpr uint32_t SEGMENT_SIZE = LLC_SETS / 3;
constexpr uint32_t ADAPT_PERIOD = 4096;

// --- Per-line metadata ---
struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
};

// --- Per-segment metadata ---
struct SegmentMeta {
    uint64_t accesses;
    uint64_t hits;
    uint64_t misses;
    uint32_t bypass_threshold; // For irregular segment
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SegmentMeta, 3> segment_meta;
uint64_t global_hits = 0, global_misses = 0;

// Helper: segment assignment
inline uint8_t get_segment(uint32_t set) {
    // 0: spatial, 1: temporal, 2: irregular
    if (set < SEGMENT_SIZE) return 0;
    else if (set < 2*SEGMENT_SIZE) return 1;
    else return 2;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_meta[set][way] = {0, RRIP_MAX};
    for (uint8_t seg = 0; seg < 3; ++seg) {
        segment_meta[seg].accesses = 0;
        segment_meta[seg].hits = 0;
        segment_meta[seg].misses = 0;
        segment_meta[seg].bypass_threshold = 4; // start with conservative bypass
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
    uint8_t seg = get_segment(set);

    // Targeted bypass for irregular segment
    if (seg == 2) {
        // If all lines have RRIP_MAX, and recent misses > threshold, bypass
        bool all_high_rrip = true;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (line_meta[set][w].rrip < RRIP_MAX) {
                all_high_rrip = false;
                break;
            }
        if (all_high_rrip && segment_meta[seg].misses > segment_meta[seg].bypass_threshold)
            return LLC_WAYS; // bypass insertion
    }

    // Standard RRIP victim selection
    uint8_t max_rrip = 0;
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        if (line_meta[set][w].rrip > max_rrip)
            max_rrip = line_meta[set][w].rrip;

    for (uint32_t round = 0; round < 2; ++round) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (line_meta[set][w].rrip == max_rrip)
                return w;
        // If not found, increment all RRIPs and retry
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (line_meta[set][w].rrip < RRIP_MAX)
                line_meta[set][w].rrip++;
    }
    return 0; // fallback
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
    uint8_t seg = get_segment(set);
    SegmentMeta& smeta = segment_meta[seg];
    smeta.accesses++;
    if (hit) {
        smeta.hits++;
        global_hits++;
    } else {
        smeta.misses++;
        global_misses++;
    }

    // Adapt bypass threshold for irregular segment every ADAPT_PERIOD
    if (seg == 2 && smeta.accesses % ADAPT_PERIOD == 0) {
        double hit_rate = (smeta.hits + 1.0) / (smeta.accesses + 1.0);
        if (hit_rate < 0.10 && smeta.bypass_threshold < LLC_WAYS)
            smeta.bypass_threshold++; // more bypass if hit rate is low
        else if (hit_rate > 0.20 && smeta.bypass_threshold > 1)
            smeta.bypass_threshold--; // less bypass if hit rate improves
        smeta.hits = smeta.misses = 0;
    }

    // Bypass logic: if victim is LLC_WAYS, do not insert
    if (way == LLC_WAYS) return;

    auto& lmeta = line_meta[set][way];
    lmeta.tag = paddr >> 6;

    // Insert/promote based on segment
    if (hit) {
        lmeta.rrip = 0; // promote on hit
    } else {
        if (seg == 0) { // spatial
            lmeta.rrip = RRIP_INSERT_SPATIAL;
        } else if (seg == 1) { // temporal
            lmeta.rrip = RRIP_INSERT_TEMPORAL;
        } else { // irregular
            lmeta.rrip = RRIP_INSERT_IRREGULAR;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SARRIP-TB Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
    for (uint8_t seg = 0; seg < 3; ++seg)
        std::cout << "Segment " << (seg == 0 ? "Spatial" : seg == 1 ? "Temporal" : "Irregular")
                  << ": Bypass Threshold = " << segment_meta[seg].bypass_threshold << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[SARRIP-TB Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
    for (uint8_t seg = 0; seg < 3; ++seg)
        std::cout << "[Segment " << (seg == 0 ? "Spatial" : seg == 1 ? "Temporal" : "Irregular")
                  << "] Accesses: " << segment_meta[seg].accesses
                  << ", Hits: " << segment_meta[seg].hits
                  << ", Misses: " << segment_meta[seg].misses
                  << ", Bypass Threshold: " << segment_meta[seg].bypass_threshold
                  << std::endl;
}