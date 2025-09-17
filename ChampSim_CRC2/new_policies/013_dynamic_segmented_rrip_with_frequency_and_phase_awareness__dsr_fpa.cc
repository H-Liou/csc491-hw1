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
constexpr uint32_t ADAPT_PERIOD = 2048; // accesses between adaptation

enum SegmentType : uint8_t { SEG_SRRIP=0, SEG_LFU=1, SEG_SPATIAL=2 };

// --- Per-line metadata ---
struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
    uint8_t freq;        // Frequency counter (LFU-style)
    uint64_t last_pc;    // Last PC that accessed this line
    uint64_t last_paddr; // Last paddr for spatial locality
};

// --- Per-set metadata ---
struct SetMeta {
    uint64_t hits, misses, accesses;
    uint64_t last_adapt_access;
    // PC signature history for phase detection
    std::array<uint64_t, 4> last_pcs;
    uint32_t pc_ptr;
    // Spatial locality detection
    std::array<uint64_t, 4> last_paddrs;
    std::array<int64_t, 3> last_strides;
    uint32_t paddr_ptr;
    // Segment type
    SegmentType segment;
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetMeta, LLC_SETS> set_meta;
uint64_t global_hits = 0, global_misses = 0;

// Initialize replacement state
void InitReplacementState() {
    // Partition sets into segments: 1/3 SRRIP, 1/3 LFU, 1/3 Spatial
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way] = {0, SRRIP_MAX, 0, 0, 0};
        }
        set_meta[set].hits = set_meta[set].misses = set_meta[set].accesses = 0;
        set_meta[set].last_adapt_access = 0;
        set_meta[set].last_pcs.fill(0);
        set_meta[set].pc_ptr = 0;
        set_meta[set].last_paddrs.fill(0);
        set_meta[set].last_strides.fill(0);
        set_meta[set].paddr_ptr = 0;
        // Initial segment assignment
        if (set < LLC_SETS/3)
            set_meta[set].segment = SEG_SRRIP;
        else if (set < 2*LLC_SETS/3)
            set_meta[set].segment = SEG_LFU;
        else
            set_meta[set].segment = SEG_SPATIAL;
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
    SegmentType seg = set_meta[set].segment;
    uint32_t victim = 0;

    if (seg == SEG_SRRIP) {
        // SRRIP: pick line with max RRIP, break ties randomly
        uint8_t max_rrip = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (line_meta[set][w].rrip > max_rrip)
                max_rrip = line_meta[set][w].rrip;
        std::vector<uint32_t> candidates;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (line_meta[set][w].rrip == max_rrip)
                candidates.push_back(w);
        victim = candidates[rand() % candidates.size()];
    }
    else if (seg == SEG_LFU) {
        // LFU: pick line with lowest freq, break ties by RRIP
        uint8_t min_freq = 255;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (line_meta[set][w].freq < min_freq)
                min_freq = line_meta[set][w].freq;
        std::vector<uint32_t> candidates;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (line_meta[set][w].freq == min_freq)
                candidates.push_back(w);
        // Among candidates, pick highest RRIP
        uint8_t max_rrip = 0;
        for (auto w : candidates)
            if (line_meta[set][w].rrip > max_rrip)
                max_rrip = line_meta[set][w].rrip;
        std::vector<uint32_t> rrip_candidates;
        for (auto w : candidates)
            if (line_meta[set][w].rrip == max_rrip)
                rrip_candidates.push_back(w);
        victim = rrip_candidates[rand() % rrip_candidates.size()];
    }
    else { // SEG_SPATIAL
        // Spatial: pick line whose last_paddr is farthest from current paddr stride
        int64_t best_dist = -1;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            int64_t dist = std::abs(int64_t(line_meta[set][w].last_paddr) - int64_t(paddr));
            if (dist > best_dist) {
                best_dist = dist;
                victim = w;
            }
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
    // Update global stats
    if (hit) global_hits++; else global_misses++;
    auto& smeta = set_meta[set];
    smeta.accesses++;
    if (hit) smeta.hits++; else smeta.misses++;

    // Update PC history for phase detection
    smeta.last_pcs[smeta.pc_ptr] = PC;
    smeta.pc_ptr = (smeta.pc_ptr + 1) % smeta.last_pcs.size();

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
    // Detect control-dominated phase: if PCs are diverse
    bool control_phase = false;
    if (smeta.accesses > 4) {
        std::unordered_map<uint64_t, int> pc_count;
        for (auto pc : smeta.last_pcs) pc_count[pc]++;
        control_phase = (pc_count.size() > 2); // more than 2 distinct PCs
    }

    // Adapt segment every ADAPT_PERIOD accesses
    if (smeta.accesses - smeta.last_adapt_access >= ADAPT_PERIOD) {
        // If spatial locality is high, use spatial segment
        if (spatial_local) {
            smeta.segment = SEG_SPATIAL;
        }
        // If control-dominated, use LFU segment
        else if (control_phase) {
            smeta.segment = SEG_LFU;
        }
        // Otherwise, use SRRIP segment
        else {
            smeta.segment = SEG_SRRIP;
        }
        smeta.last_adapt_access = smeta.accesses;
        smeta.hits = smeta.misses = 0;
    }

    // Update per-line metadata
    auto& lmeta = line_meta[set][way];
    lmeta.tag = paddr >> 6;
    lmeta.last_pc = PC;
    lmeta.last_paddr = paddr;

    if (hit) {
        // Promotion rules
        if (smeta.segment == SEG_SRRIP)
            lmeta.rrip = 0;
        else if (smeta.segment == SEG_LFU)
            lmeta.freq = std::min(lmeta.freq + 1, uint8_t(255));
        else // SEG_SPATIAL
            lmeta.rrip = 0;
    } else {
        // Insertion rules
        if (smeta.segment == SEG_SRRIP) {
            lmeta.rrip = SRRIP_INSERT;
            lmeta.freq = 1;
        }
        else if (smeta.segment == SEG_LFU) {
            lmeta.rrip = SRRIP_MAX;
            lmeta.freq = 1;
        }
        else { // SEG_SPATIAL
            lmeta.rrip = 0;
            lmeta.freq = 1;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DSR-FPA Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
    std::array<uint32_t, 3> seg_counts = {0,0,0};
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        seg_counts[set_meta[set].segment]++;
    std::cout << "Sets in SRRIP: " << seg_counts[SEG_SRRIP]
              << ", LFU: " << seg_counts[SEG_LFU]
              << ", Spatial: " << seg_counts[SEG_SPATIAL] << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[DSR-FPA Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
    uint32_t sample_set = 0;
    std::cout << "[Set " << sample_set << "] Segment: "
              << (set_meta[sample_set].segment == SEG_SRRIP ? "SRRIP" :
                  set_meta[sample_set].segment == SEG_LFU ? "LFU" : "Spatial")
              << ", Hits: " << set_meta[sample_set].hits
              << ", Misses: " << set_meta[sample_set].misses
              << std::endl;
}