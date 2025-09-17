#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int RRIP_BITS = 2;
constexpr int RRIP_MAX = (1 << RRIP_BITS) - 1; // 3
constexpr int RRIP_LONG = RRIP_MAX; // 3: streaming, evict fast
constexpr int RRIP_MID = 1;         // 1: spatial, moderate retention
constexpr int RRIP_SHORT = 0;       // 0: temporal, retain long

// Per-set reuse counter (saturating [0,7])
struct SetState {
    std::vector<uint8_t> rrip;
    std::vector<uint64_t> tags;
    std::vector<bool> valid;
    uint8_t reuse_counter; // 0: streaming, 1-3: spatial, 4-7: temporal
};

std::vector<SetState> sets(LLC_SETS);

// Global streaming detector
uint32_t global_miss_count = 0, global_access_count = 0;
uint8_t global_streaming_mode = 0; // 1: streaming detected, 0: normal

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.rrip.assign(LLC_WAYS, RRIP_MAX);
        set.tags.assign(LLC_WAYS, 0);
        set.valid.assign(LLC_WAYS, false);
        set.reuse_counter = 3; // Start as spatial
    }
    global_miss_count = 0;
    global_access_count = 0;
    global_streaming_mode = 0;
}

// --- Victim selection (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState& s = sets[set];
    // Prefer invalid
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!s.valid[way])
            return way;
    }
    // SRRIP: Find RRIP_MAX
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.rrip[way] == RRIP_MAX)
                return way;
        }
        // Age all lines
        for (auto& r : s.rrip)
            if (r < RRIP_MAX) r++;
    }
}

// --- Global streaming detector ---
void UpdateGlobalStreaming(bool miss) {
    global_access_count++;
    if (miss) global_miss_count++;
    if (global_access_count >= 2048) {
        // If miss rate > 60%, enable streaming mode for next period
        if (global_miss_count * 100 / global_access_count > 60)
            global_streaming_mode = 1;
        else
            global_streaming_mode = 0;
        global_access_count = 0;
        global_miss_count = 0;
    }
}

// --- Replacement state update ---
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
    SetState& s = sets[set];
    uint64_t line_addr = paddr >> 6;

    // Update global streaming detector
    UpdateGlobalStreaming(!hit);

    // Update per-set reuse counter
    if (hit) {
        // On hit, promote block and increment reuse counter
        s.rrip[way] = RRIP_SHORT;
        if (s.reuse_counter < 7) s.reuse_counter++;
    } else {
        // On miss, decay reuse counter
        if (s.reuse_counter > 0) s.reuse_counter--;
    }

    // Determine insertion RRIP
    uint8_t ins_rrip = RRIP_MID;
    if (global_streaming_mode) {
        ins_rrip = RRIP_LONG; // Streaming detected, evict fast
    } else {
        if (s.reuse_counter >= 4)      ins_rrip = RRIP_SHORT; // temporal
        else if (s.reuse_counter >= 1) ins_rrip = RRIP_MID;   // spatial
        else                           ins_rrip = RRIP_LONG;  // streaming
    }

    // Insert/update block
    s.rrip[way] = ins_rrip;
    s.tags[way] = line_addr;
    s.valid[way] = true;
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "HDRRIP: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}