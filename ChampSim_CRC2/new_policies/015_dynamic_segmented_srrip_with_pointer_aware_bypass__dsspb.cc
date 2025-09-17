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

constexpr uint8_t SRRIP_BITS = 2;
constexpr uint8_t SRRIP_MAX = (1 << SRRIP_BITS) - 1; // 3
constexpr uint8_t SRRIP_INSERT = SRRIP_MAX - 1;      // 2
constexpr uint32_t SEGMENT_SIZE = LLC_SETS / 2;      // Half sets for each segment
constexpr uint32_t ADAPT_PERIOD = 2048;              // accesses between adaptation

// --- Per-line metadata ---
struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
    bool pointer_like;
};

// --- Per-set metadata ---
struct SetMeta {
    uint64_t hits, misses, accesses;
    uint64_t last_adapt_access;
    // Pointer-chase detection
    std::array<uint64_t, 4> last_paddrs;
    std::array<uint64_t, 4> last_pcs;
    uint32_t paddr_ptr, pc_ptr;
    uint32_t pointer_chase_cnt;
    uint32_t regular_cnt;
    // Segment mode: 0 = regular (spatial), 1 = pointer-heavy
    uint8_t mode;
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetMeta, LLC_SETS> set_meta;
uint64_t global_hits = 0, global_misses = 0;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way] = {0, SRRIP_MAX, false};
        }
        set_meta[set].hits = set_meta[set].misses = set_meta[set].accesses = 0;
        set_meta[set].last_adapt_access = 0;
        set_meta[set].last_paddrs.fill(0);
        set_meta[set].last_pcs.fill(0);
        set_meta[set].paddr_ptr = set_meta[set].pc_ptr = 0;
        set_meta[set].pointer_chase_cnt = 0;
        set_meta[set].regular_cnt = 0;
        // Segment assignment: first half regular, second half pointer-heavy
        set_meta[set].mode = (set < SEGMENT_SIZE) ? 0 : 1;
    }
    global_hits = global_misses = 0;
}

// Helper: detect pointer-like access
bool is_pointer_chase(uint32_t set, uint64_t paddr, uint64_t PC) {
    auto& smeta = set_meta[set];
    // If stride is irregular and PC is diverse, likely pointer-chase
    uint64_t prev_paddr = smeta.last_paddrs[smeta.paddr_ptr];
    int64_t stride = int64_t(paddr) - int64_t(prev_paddr);
    smeta.last_paddrs[smeta.paddr_ptr] = paddr;
    smeta.paddr_ptr = (smeta.paddr_ptr + 1) % smeta.last_paddrs.size();

    smeta.last_pcs[smeta.pc_ptr] = PC;
    smeta.pc_ptr = (smeta.pc_ptr + 1) % smeta.last_pcs.size();

    bool stride_irregular = false;
    if (smeta.accesses > 4) {
        std::array<int64_t, 3> strides;
        for (size_t i = 1; i < smeta.last_paddrs.size(); ++i)
            strides[i-1] = int64_t(smeta.last_paddrs[i]) - int64_t(smeta.last_paddrs[i-1]);
        int64_t base_stride = strides[0];
        stride_irregular = std::any_of(strides.begin(), strides.end(),
            [base_stride](int64_t s){ return std::abs(s - base_stride) > 128; });
    }

    std::unordered_map<uint64_t, int> pc_count;
    for (auto pc : smeta.last_pcs) pc_count[pc]++;
    bool diverse_pc = (pc_count.size() > 2);

    return stride_irregular && diverse_pc;
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
    // Pointer-heavy segment: prefer victim with highest RRIP and pointer_like
    // Regular segment: prefer victim with highest RRIP, ignore pointer_like
    uint8_t max_rrip = 0;
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        if (line_meta[set][w].rrip > max_rrip)
            max_rrip = line_meta[set][w].rrip;

    uint32_t victim = 0;
    if (smeta.mode == 1) {
        // Pointer-heavy: among max RRIP, prefer pointer_like
        bool found = false;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (line_meta[set][w].rrip == max_rrip && line_meta[set][w].pointer_like) {
                victim = w;
                found = true;
                break;
            }
        }
        if (!found) {
            // fallback: max RRIP
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (line_meta[set][w].rrip == max_rrip)
                    victim = w;
        }
    } else {
        // Regular: among max RRIP, pick first
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (line_meta[set][w].rrip == max_rrip)
                victim = w;
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
    if (hit) { smeta.hits++; global_hits++; }
    else { smeta.misses++; global_misses++; }

    bool pointer_access = is_pointer_chase(set, paddr, PC);
    if (pointer_access) smeta.pointer_chase_cnt++;
    else smeta.regular_cnt++;

    // Adapt segment mode every ADAPT_PERIOD accesses
    if (smeta.accesses - smeta.last_adapt_access >= ADAPT_PERIOD) {
        // If pointer accesses dominate, switch to pointer-heavy
        if (smeta.pointer_chase_cnt > smeta.regular_cnt)
            smeta.mode = 1;
        else
            smeta.mode = 0;
        smeta.last_adapt_access = smeta.accesses;
        smeta.pointer_chase_cnt = smeta.regular_cnt = 0;
        smeta.hits = smeta.misses = 0;
    }

    auto& lmeta = line_meta[set][way];
    lmeta.tag = paddr >> 6;
    lmeta.pointer_like = pointer_access;

    // Insertion/promotion policy
    if (hit) {
        lmeta.rrip = 0; // promote on hit
    } else {
        if (smeta.mode == 1 && pointer_access) {
            // Pointer-heavy: insert with max RRIP, possible bypass
            lmeta.rrip = SRRIP_MAX;
            // Bypass: do not insert, if victim was pointer-like and high RRIP
            if (line_meta[set][way].pointer_like && line_meta[set][way].rrip == SRRIP_MAX) {
                // Do not update metadata (simulate bypass)
                return;
            }
        } else {
            // Regular: insert with low RRIP for spatial locality
            lmeta.rrip = SRRIP_INSERT;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DSSPB Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
    std::array<uint32_t, 2> mode_counts = {0,0};
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        mode_counts[set_meta[set].mode]++;
    std::cout << "Sets in Regular: " << mode_counts[0]
              << ", Pointer-heavy: " << mode_counts[1] << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[DSSPB Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
    uint32_t sample_set = 0;
    std::cout << "[Set " << sample_set << "] Mode: "
              << (set_meta[sample_set].mode == 0 ? "Regular" : "Pointer-heavy")
              << ", Hits: " << set_meta[sample_set].hits
              << ", Misses: " << set_meta[sample_set].misses
              << std::endl;
}