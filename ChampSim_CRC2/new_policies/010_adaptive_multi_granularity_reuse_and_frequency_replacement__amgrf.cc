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

constexpr uint32_t ADAPT_PERIOD = 1024; // accesses between adaptation

// --- Per-line metadata ---
struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
    uint32_t freq;        // Frequency counter (LFU-style)
    uint64_t last_pc;     // Last PC that accessed this line
    uint64_t last_paddr;  // Last paddr for spatial locality
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
    // Mode: 0=SRRIP, 1=LFU, 2=Spatial
    uint8_t mode;
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetMeta, LLC_SETS> set_meta;
uint64_t global_hits = 0, global_misses = 0;

// Initialize replacement state
void InitReplacementState() {
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
    // Prefer lines with highest RRIP and lowest frequency
    uint32_t victim = 0;
    uint8_t max_rrip = 0;
    uint32_t min_freq = UINT32_MAX;

    // Find max RRIP among ways
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        if (line_meta[set][w].rrip > max_rrip)
            max_rrip = line_meta[set][w].rrip;

    // Among lines with max RRIP, pick the one with lowest frequency
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (line_meta[set][w].rrip == max_rrip) {
            if (line_meta[set][w].freq < min_freq) {
                min_freq = line_meta[set][w].freq;
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

    // Adapt mode every ADAPT_PERIOD accesses
    if (smeta.accesses - smeta.last_adapt_access >= ADAPT_PERIOD) {
        double hit_rate = smeta.accesses ? (double)smeta.hits / smeta.accesses : 0.0;
        // If spatial locality is high, use spatial mode
        if (spatial_local) {
            smeta.mode = 2; // Spatial
        }
        // If control-dominated, use LFU mode
        else if (control_phase) {
            smeta.mode = 1; // LFU
        }
        // Otherwise, use SRRIP
        else {
            smeta.mode = 0; // SRRIP
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
        lmeta.rrip = 0; // Promote on hit
        lmeta.freq = std::min(lmeta.freq + 1, 255u); // saturating
    } else {
        // Insertion policy based on mode
        if (smeta.mode == 2) { // Spatial
            lmeta.rrip = 0;
            lmeta.freq = 1;
        } else if (smeta.mode == 1) { // LFU
            lmeta.rrip = SRRIP_MAX;
            lmeta.freq = 1;
        } else { // SRRIP
            lmeta.rrip = SRRIP_INSERT;
            lmeta.freq = 1;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "AMGRF Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
    std::array<uint32_t, 3> mode_counts = {0,0,0};
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        mode_counts[set_meta[set].mode]++;
    std::cout << "Sets in SRRIP: " << mode_counts[0]
              << ", LFU: " << mode_counts[1]
              << ", Spatial: " << mode_counts[2] << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[AMGRF Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
    uint32_t sample_set = 0;
    std::cout << "[Set " << sample_set << "] Mode: "
              << (set_meta[sample_set].mode == 0 ? "SRRIP" :
                  set_meta[sample_set].mode == 1 ? "LFU" : "Spatial")
              << ", Hits: " << set_meta[sample_set].hits
              << ", Misses: " << set_meta[sample_set].misses
              << std::endl;
}