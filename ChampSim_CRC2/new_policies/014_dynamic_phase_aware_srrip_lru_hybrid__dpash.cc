#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr uint8_t SRRIP_BITS = 2;
constexpr uint8_t SRRIP_MAX = (1 << SRRIP_BITS) - 1; // 3
constexpr uint8_t SRRIP_INSERT = SRRIP_MAX - 1;      // 2
constexpr uint32_t PHASE_PERIOD = 512;

// --- Per-line metadata ---
struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
    uint8_t lru;
    uint64_t last_paddr;
};

// --- Per-set metadata ---
struct SetMeta {
    uint64_t hits, misses, accesses;
    uint64_t last_adapt_access;
    // For phase detection
    std::array<uint64_t, 4> last_paddrs;
    uint32_t paddr_ptr;
    std::array<int64_t, 3> last_strides;
    // Mode: 0=SRRIP, 1=LRU
    uint8_t mode;
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetMeta, LLC_SETS> set_meta;
uint64_t global_hits = 0, global_misses = 0;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way] = {0, SRRIP_MAX, uint8_t(way), 0};
        }
        set_meta[set].hits = set_meta[set].misses = set_meta[set].accesses = 0;
        set_meta[set].last_adapt_access = 0;
        set_meta[set].last_paddrs.fill(0);
        set_meta[set].paddr_ptr = 0;
        set_meta[set].last_strides.fill(0);
        set_meta[set].mode = 0; // Start with SRRIP
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
    auto& smeta = set_meta[set];
    if (smeta.mode == 0) { // SRRIP
        // Find block with RRIP==SRRIP_MAX
        for (uint32_t tries = 0; tries < 2; ++tries) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way) {
                if (line_meta[set][way].rrip == SRRIP_MAX)
                    return way;
            }
            // If none found, increment RRIP of all lines and retry
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                line_meta[set][way].rrip = std::min(SRRIP_MAX, line_meta[set][way].rrip + 1);
        }
        // Fallback: evict way 0
        return 0;
    } else { // LRU
        // Find block with max LRU value
        uint8_t max_lru = 0;
        uint32_t victim = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_meta[set][way].lru >= max_lru) {
                max_lru = line_meta[set][way].lru;
                victim = way;
            }
        }
        return victim;
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
    auto& smeta = set_meta[set];
    smeta.accesses++;
    if (hit) { global_hits++; smeta.hits++; }
    else     { global_misses++; smeta.misses++; }

    // Update stride history for spatial locality detection
    uint64_t prev_paddr = smeta.last_paddrs[smeta.paddr_ptr];
    int64_t stride = int64_t(paddr) - int64_t(prev_paddr);
    if (smeta.paddr_ptr > 0)
        smeta.last_strides[smeta.paddr_ptr - 1] = stride;
    smeta.last_paddrs[smeta.paddr_ptr] = paddr;
    smeta.paddr_ptr = (smeta.paddr_ptr + 1) % smeta.last_paddrs.size();

    // Detect spatial locality: if strides are consistent and small
    bool spatial_local = false;
    if (smeta.accesses > 4) {
        int64_t base_stride = smeta.last_strides[0];
        spatial_local = std::all_of(smeta.last_strides.begin(), smeta.last_strides.end(),
                                    [base_stride](int64_t s) { return std::abs(s - base_stride) <= 64; });
    }

    // Adapt mode every PHASE_PERIOD accesses
    if (smeta.accesses - smeta.last_adapt_access >= PHASE_PERIOD) {
        double hit_rate = smeta.accesses ? (double)smeta.hits / smeta.accesses : 0.0;
        // If spatial locality is high and hit rate is good, use SRRIP
        if (spatial_local && hit_rate > 0.25) {
            smeta.mode = 0; // SRRIP
        }
        // If hit rate is poor or spatial locality is low, use LRU
        else {
            smeta.mode = 1; // LRU
        }
        smeta.last_adapt_access = smeta.accesses;
        smeta.hits = smeta.misses = 0;
    }

    // Update per-line metadata
    auto& lmeta = line_meta[set][way];
    lmeta.tag = paddr >> 6;
    lmeta.last_paddr = paddr;

    if (smeta.mode == 0) { // SRRIP
        if (hit) {
            lmeta.rrip = 0; // Promote on hit
        } else {
            lmeta.rrip = SRRIP_INSERT; // Insert with long interval
        }
        // LRU stack maintenance (for hybrid fallback)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            line_meta[set][w].lru = std::min(uint8_t(LLC_WAYS-1), line_meta[set][w].lru + 1);
        lmeta.lru = 0;
    } else { // LRU
        // LRU stack maintenance
        uint8_t old_lru = lmeta.lru;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (line_meta[set][w].lru < old_lru)
                line_meta[set][w].lru++;
        }
        lmeta.lru = 0;
        // RRIP maintenance for fallback
        lmeta.rrip = SRRIP_MAX;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DPASH Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
    std::array<uint32_t, 2> mode_counts = {0,0};
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        mode_counts[set_meta[set].mode]++;
    std::cout << "Sets in SRRIP: " << mode_counts[0]
              << ", LRU: " << mode_counts[1] << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[DPASH Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
    uint32_t sample_set = 0;
    std::cout << "[Set " << sample_set << "] Mode: "
              << (set_meta[sample_set].mode == 0 ? "SRRIP" : "LRU")
              << ", Hits: " << set_meta[sample_set].hits
              << ", Misses: " << set_meta[sample_set].misses
              << std::endl;
}