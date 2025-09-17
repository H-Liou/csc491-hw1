#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr uint8_t SRRIP_BITS = 2;
constexpr uint8_t SRRIP_MAX = (1 << SRRIP_BITS) - 1; // 3
constexpr uint8_t SRRIP_INSERT = SRRIP_MAX - 1;      // 2

constexpr uint32_t DYNAMIC_PERIOD = 2048; // accesses between adaptation

// --- Per-line metadata ---
struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
    uint64_t last_paddr;
    uint32_t reuse_count;
};

// --- Per-set metadata ---
struct SetMeta {
    // Recent access history for stride detection
    std::array<uint64_t, 4> last_paddrs;
    std::array<int64_t, 3> last_strides;
    uint32_t history_ptr;
    // Hit/miss counters for phase adaptation
    uint64_t hits, misses;
    uint64_t accesses, last_switch_access;
    // Current insertion mode: 0=SRRIP, 1=BIP, 2=Spatial
    uint8_t mode;
    // For spatial locality detection
    uint32_t spatial_hits, spatial_accesses;
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetMeta, LLC_SETS> set_meta;
uint64_t global_hits = 0, global_misses = 0;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way] = {0, SRRIP_MAX, 0, 0};
        }
        set_meta[set].last_paddrs.fill(0);
        set_meta[set].last_strides.fill(0);
        set_meta[set].history_ptr = 0;
        set_meta[set].hits = set_meta[set].misses = set_meta[set].accesses = 0;
        set_meta[set].last_switch_access = 0;
        set_meta[set].mode = 0; // Start with SRRIP
        set_meta[set].spatial_hits = set_meta[set].spatial_accesses = 0;
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
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (line_meta[set][w].rrip == SRRIP_MAX)
                return w;
        }
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (line_meta[set][w].rrip < SRRIP_MAX)
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
    // Update global stats
    if (hit) global_hits++; else global_misses++;
    set_meta[set].accesses++;
    if (hit) set_meta[set].hits++; else set_meta[set].misses++;

    // Update stride history for spatial locality detection
    auto& smeta = set_meta[set];
    uint64_t prev_paddr = smeta.last_paddrs[smeta.history_ptr];
    int64_t stride = int64_t(paddr) - int64_t(prev_paddr);
    if (smeta.history_ptr > 0)
        smeta.last_strides[smeta.history_ptr - 1] = stride;
    smeta.last_paddrs[smeta.history_ptr] = paddr;
    smeta.history_ptr = (smeta.history_ptr + 1) % smeta.last_paddrs.size();

    // Detect spatial locality: if strides are consistent and small
    bool spatial_local = false;
    if (smeta.accesses > 4) {
        int64_t base_stride = smeta.last_strides[0];
        spatial_local = std::all_of(smeta.last_strides.begin(), smeta.last_strides.end(),
                                    [base_stride](int64_t s) { return std::abs(s - base_stride) <= 64; });
    }

    // Track spatial hits
    if (spatial_local) smeta.spatial_accesses++;
    if (spatial_local && hit) smeta.spatial_hits++;

    // Per-set adaptation: every DYNAMIC_PERIOD accesses, switch mode
    if (smeta.accesses - smeta.last_switch_access >= DYNAMIC_PERIOD) {
        double hit_rate = smeta.accesses ? (double)smeta.hits / smeta.accesses : 0.0;
        double spatial_rate = smeta.spatial_accesses ? (double)smeta.spatial_hits / smeta.spatial_accesses : 0.0;

        // If spatial locality is high, use spatial mode (insert with high priority)
        if (spatial_rate > 0.6 && smeta.spatial_accesses > 100) {
            smeta.mode = 2; // Spatial
        }
        // If hit rate is high, use SRRIP
        else if (hit_rate > 0.4) {
            smeta.mode = 0; // SRRIP
        }
        // Otherwise, use BIP (pollution resistance)
        else {
            smeta.mode = 1; // BIP
        }
        smeta.last_switch_access = smeta.accesses;
        smeta.hits = smeta.misses = smeta.accesses = 0;
        smeta.spatial_hits = smeta.spatial_accesses = 0;
    }

    // Update per-line metadata
    auto& lmeta = line_meta[set][way];
    if (hit) {
        lmeta.rrip = 0; // Promote on hit
        lmeta.reuse_count++;
        lmeta.last_paddr = paddr;
        lmeta.tag = paddr >> 6;
    } else {
        lmeta.tag = paddr >> 6;
        lmeta.last_paddr = paddr;
        lmeta.reuse_count = 0;
        // Insertion policy based on mode
        if (smeta.mode == 0) { // SRRIP
            lmeta.rrip = SRRIP_INSERT;
        } else if (smeta.mode == 1) { // BIP
            static uint32_t bip_counter = 0;
            bip_counter++;
            if (bip_counter % 32 == 0)
                lmeta.rrip = SRRIP_INSERT;
            else
                lmeta.rrip = SRRIP_MAX;
        } else { // Spatial
            lmeta.rrip = 0; // Insert with high priority
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DMRRR Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
    // Print mode distribution
    std::array<uint32_t, 3> mode_counts = {0,0,0};
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        mode_counts[set_meta[set].mode]++;
    std::cout << "Sets in SRRIP: " << mode_counts[0]
              << ", BIP: " << mode_counts[1]
              << ", Spatial: " << mode_counts[2] << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[DMRRR Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
    uint32_t sample_set = 0;
    std::cout << "[Set " << sample_set << "] Mode: "
              << (set_meta[sample_set].mode == 0 ? "SRRIP" :
                  set_meta[sample_set].mode == 1 ? "BIP" : "Spatial")
              << ", Hits: " << set_meta[sample_set].hits
              << ", Misses: " << set_meta[sample_set].misses
              << ", Spatial Hits: " << set_meta[sample_set].spatial_hits
              << ", Spatial Accesses: " << set_meta[sample_set].spatial_accesses
              << std::endl;
}