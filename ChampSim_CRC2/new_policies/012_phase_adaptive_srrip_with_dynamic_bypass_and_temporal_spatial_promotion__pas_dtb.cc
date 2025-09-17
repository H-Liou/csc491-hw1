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

constexpr uint32_t PHASE_WINDOW = 128; // accesses for phase detection
constexpr uint32_t BYPASS_WINDOW = 32; // accesses for bypass frequency

// --- Per-line metadata ---
struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
    uint64_t last_pc;
    uint64_t last_paddr;
    uint32_t reuse_counter; // tracks hits for temporal locality
};

// --- Per-set metadata ---
struct SetMeta {
    // Phase detection
    uint32_t accesses;
    uint32_t hits;
    uint32_t misses;
    std::array<uint64_t, 4> last_pcs;
    uint32_t pc_ptr;
    std::array<uint64_t, 4> last_paddrs;
    std::array<int64_t, 3> last_strides;
    uint32_t paddr_ptr;
    // Bypass stats
    uint32_t bypassed;
    // Phase flags
    bool control_phase;
    bool spatial_phase;
    bool temporal_phase;
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetMeta, LLC_SETS> set_meta;
uint64_t global_hits = 0, global_misses = 0, global_bypass = 0;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way] = {0, SRRIP_MAX, 0, 0, 0};
        }
        set_meta[set].accesses = set_meta[set].hits = set_meta[set].misses = 0;
        set_meta[set].last_pcs.fill(0);
        set_meta[set].pc_ptr = 0;
        set_meta[set].last_paddrs.fill(0);
        set_meta[set].last_strides.fill(0);
        set_meta[set].paddr_ptr = 0;
        set_meta[set].bypassed = 0;
        set_meta[set].control_phase = false;
        set_meta[set].spatial_phase = false;
        set_meta[set].temporal_phase = false;
    }
    global_hits = global_misses = global_bypass = 0;
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
    // Dynamic bypass: If in control phase, with high miss rate, and recent bypasses, bypass insertion
    auto& smeta = set_meta[set];
    if (smeta.control_phase && smeta.misses > (PHASE_WINDOW * 0.7)) {
        smeta.bypassed++;
        global_bypass++;
        return LLC_WAYS; // signal bypass (no replacement)
    }

    // Standard SRRIP victim selection
    // Find max RRIP among ways
    uint8_t max_rrip = 0;
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        if (line_meta[set][w].rrip > max_rrip)
            max_rrip = line_meta[set][w].rrip;

    // Among lines with max RRIP, pick the one with lowest reuse_counter
    uint32_t victim = 0;
    uint32_t min_reuse = UINT32_MAX;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (line_meta[set][w].rrip == max_rrip) {
            if (line_meta[set][w].reuse_counter < min_reuse) {
                min_reuse = line_meta[set][w].reuse_counter;
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
    auto& smeta = set_meta[set];
    smeta.accesses++;
    if (hit) { global_hits++; smeta.hits++; }
    else     { global_misses++; smeta.misses++; }

    // Update PC history for control phase detection
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
    smeta.spatial_phase = false;
    if (smeta.accesses > 4) {
        int64_t base_stride = smeta.last_strides[0];
        smeta.spatial_phase = std::all_of(smeta.last_strides.begin(), smeta.last_strides.end(),
                                    [base_stride](int64_t s) { return std::abs(s - base_stride) <= 64 && std::abs(base_stride) > 0; });
    }

    // Detect control-dominated phase: if PCs are diverse
    smeta.control_phase = false;
    if (smeta.accesses > 4) {
        std::unordered_map<uint64_t, int> pc_count;
        for (auto pc : smeta.last_pcs) pc_count[pc]++;
        smeta.control_phase = (pc_count.size() > 2); // more than 2 distinct PCs
    }

    // Detect temporal locality: if multiple hits in the window
    smeta.temporal_phase = (smeta.hits > (PHASE_WINDOW * 0.2));

    // Reset phase window
    if (smeta.accesses % PHASE_WINDOW == 0) {
        smeta.hits = smeta.misses = 0;
        smeta.bypassed = 0;
    }

    // If bypassed, do not update line metadata
    if (way == LLC_WAYS) return;

    // Update per-line metadata
    auto& lmeta = line_meta[set][way];
    lmeta.tag = paddr >> 6;
    lmeta.last_pc = PC;
    lmeta.last_paddr = paddr;

    if (hit) {
        // Promote on hit: if temporal or spatial phase, set RRIP to 0 and increment reuse
        if (smeta.temporal_phase || smeta.spatial_phase) {
            lmeta.rrip = 0;
        } else {
            lmeta.rrip = std::max(uint8_t(0), lmeta.rrip - 1);
        }
        lmeta.reuse_counter = std::min(lmeta.reuse_counter + 1, 255u);
    } else {
        // Insertion policy
        if (smeta.spatial_phase) {
            lmeta.rrip = 0; // spatial: insert with high priority
            lmeta.reuse_counter = 1;
        } else if (smeta.temporal_phase) {
            lmeta.rrip = 1; // temporal: insert with moderate priority
            lmeta.reuse_counter = 1;
        } else {
            lmeta.rrip = SRRIP_INSERT; // default SRRIP
            lmeta.reuse_counter = 0;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "PAS-DTB Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses
              << ", Total Bypassed = " << global_bypass << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[PAS-DTB Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses
              << ", Bypassed: " << global_bypass << std::endl;
    uint32_t sample_set = 0;
    auto& smeta = set_meta[sample_set];
    std::cout << "[Set " << sample_set << "] Control: " << smeta.control_phase
              << ", Spatial: " << smeta.spatial_phase
              << ", Temporal: " << smeta.temporal_phase
              << ", Hits: " << smeta.hits
              << ", Misses: " << smeta.misses
              << ", Bypassed: " << smeta.bypassed
              << std::endl;
}