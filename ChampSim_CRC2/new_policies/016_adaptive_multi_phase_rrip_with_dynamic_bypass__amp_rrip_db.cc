#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr uint8_t RRIP_BITS = 2;
constexpr uint8_t RRIP_MAX = (1 << RRIP_BITS) - 1; // 3
constexpr uint8_t RRIP_INSERT_SPATIAL = 0;         // spatial: most likely to reuse
constexpr uint8_t RRIP_INSERT_TEMPORAL = 1;        // temporal: moderate reuse
constexpr uint8_t RRIP_INSERT_IRREGULAR = RRIP_MAX;// irregular: unlikely to reuse

constexpr uint32_t PHASE_PERIOD = 1024;            // accesses between adaptation

// --- Per-line metadata ---
struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
    uint64_t last_PC;
};

// --- Per-set metadata ---
struct SetMeta {
    uint64_t hits, misses, accesses;
    uint64_t last_phase_access;
    // For phase detection
    std::array<uint64_t, 8> last_paddrs;
    std::array<uint64_t, 8> last_pcs;
    uint32_t paddr_ptr, pc_ptr;
    uint32_t spatial_cnt, temporal_cnt, irregular_cnt;
    uint8_t mode; // 0=spatial, 1=temporal, 2=irregular
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetMeta, LLC_SETS> set_meta;
uint64_t global_hits = 0, global_misses = 0;

// Helper: stride regularity and PC diversity
void analyze_access_pattern(uint32_t set, uint64_t paddr, uint64_t PC, bool &is_spatial, bool &is_irregular) {
    auto& smeta = set_meta[set];
    smeta.last_paddrs[smeta.paddr_ptr] = paddr;
    smeta.paddr_ptr = (smeta.paddr_ptr + 1) % smeta.last_paddrs.size();
    smeta.last_pcs[smeta.pc_ptr] = PC;
    smeta.pc_ptr = (smeta.pc_ptr + 1) % smeta.last_pcs.size();

    // Stride analysis
    std::array<int64_t, 7> strides;
    for (size_t i = 1; i < smeta.last_paddrs.size(); ++i)
        strides[i-1] = int64_t(smeta.last_paddrs[i]) - int64_t(smeta.last_paddrs[i-1]);
    int64_t base_stride = strides[0];
    int regular = 0, irregular = 0;
    for (auto s : strides) {
        if (std::abs(s - base_stride) < 64) regular++;
        else irregular++;
    }
    is_spatial = (regular >= 5); // mostly regular
    is_irregular = (irregular >= 5); // mostly irregular

    // PC diversity
    std::unordered_map<uint64_t, int> pc_count;
    for (auto pc : smeta.last_pcs) pc_count[pc]++;
    if (pc_count.size() > 4) is_irregular = true;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way] = {0, RRIP_MAX, 0};
        }
        set_meta[set].hits = set_meta[set].misses = set_meta[set].accesses = 0;
        set_meta[set].last_phase_access = 0;
        set_meta[set].last_paddrs.fill(0);
        set_meta[set].last_pcs.fill(0);
        set_meta[set].paddr_ptr = set_meta[set].pc_ptr = 0;
        set_meta[set].spatial_cnt = set_meta[set].temporal_cnt = set_meta[set].irregular_cnt = 0;
        set_meta[set].mode = 0; // start with spatial
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
    // Dynamic bypass: in irregular mode, bypass if all lines have high RRIP and diverse PC
    if (smeta.mode == 2) {
        bool all_high_rrip = true;
        std::unordered_map<uint64_t, int> pc_count;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (line_meta[set][w].rrip < RRIP_MAX) all_high_rrip = false;
            pc_count[line_meta[set][w].last_PC]++;
        }
        if (all_high_rrip && pc_count.size() > 4) {
            return LLC_WAYS; // bypass (no replacement)
        }
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
    auto& smeta = set_meta[set];
    smeta.accesses++;
    if (hit) { smeta.hits++; global_hits++; }
    else { smeta.misses++; global_misses++; }

    // Analyze access pattern
    bool is_spatial = false, is_irregular = false;
    analyze_access_pattern(set, paddr, PC, is_spatial, is_irregular);

    if (is_spatial) smeta.spatial_cnt++;
    else if (is_irregular) smeta.irregular_cnt++;
    else smeta.temporal_cnt++;

    // Adapt mode every PHASE_PERIOD accesses
    if (smeta.accesses - smeta.last_phase_access >= PHASE_PERIOD) {
        // Use hit rate and access pattern to decide mode
        double hit_rate = (smeta.hits + 1.0) / (smeta.accesses + 1.0);
        if (smeta.irregular_cnt > smeta.spatial_cnt && smeta.irregular_cnt > smeta.temporal_cnt)
            smeta.mode = 2; // irregular
        else if (smeta.spatial_cnt > smeta.temporal_cnt)
            smeta.mode = 0; // spatial
        else
            smeta.mode = 1; // temporal

        smeta.last_phase_access = smeta.accesses;
        smeta.spatial_cnt = smeta.temporal_cnt = smeta.irregular_cnt = 0;
        smeta.hits = smeta.misses = 0;
    }

    // Bypass logic: if victim is LLC_WAYS, do not insert
    if (way == LLC_WAYS) return;

    auto& lmeta = line_meta[set][way];
    lmeta.tag = paddr >> 6;
    lmeta.last_PC = PC;

    // Insert/promote based on mode
    if (hit) {
        lmeta.rrip = 0; // promote on hit
    } else {
        if (smeta.mode == 0) { // spatial
            lmeta.rrip = RRIP_INSERT_SPATIAL;
        } else if (smeta.mode == 1) { // temporal
            lmeta.rrip = RRIP_INSERT_TEMPORAL;
        } else { // irregular
            lmeta.rrip = RRIP_INSERT_IRREGULAR;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "AMP-RRIP-DB Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
    std::array<uint32_t, 3> mode_counts = {0,0,0};
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        mode_counts[set_meta[set].mode]++;
    std::cout << "Sets in Spatial: " << mode_counts[0]
              << ", Temporal: " << mode_counts[1]
              << ", Irregular: " << mode_counts[2] << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[AMP-RRIP-DB Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
    uint32_t sample_set = 0;
    std::cout << "[Set " << sample_set << "] Mode: "
              << (set_meta[sample_set].mode == 0 ? "Spatial" :
                  set_meta[sample_set].mode == 1 ? "Temporal" : "Irregular")
              << ", Hits: " << set_meta[sample_set].hits
              << ", Misses: " << set_meta[sample_set].misses
              << std::endl;
}