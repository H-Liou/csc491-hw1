#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int RRIP_BITS = 2;
constexpr int RRIP_MAX = (1 << RRIP_BITS) - 1; // 3
constexpr int RRIP_LONG = RRIP_MAX; // Insert with 3 for streaming
constexpr int RRIP_SHORT = 0;       // Insert with 0 for temporal
constexpr int RRIP_MID = 1;         // Insert with 1 for spatial

// Per-set signature: 8-bit, each bit is a block in the set
struct SetState {
    std::vector<uint8_t> rrip;
    std::vector<uint64_t> tags;
    std::vector<bool> valid;
    uint8_t access_signature; // 8 bits: recent access pattern
    uint8_t last_block;       // last block index accessed
    uint8_t reuse_type;       // 0: streaming, 1: spatial, 2: temporal
    uint8_t reuse_counter;    // saturating [0,7]
};

std::vector<SetState> sets(LLC_SETS);

// Global miss spike detector
uint32_t global_miss_count = 0, global_access_count = 0;
uint8_t global_aggressive_mode = 0; // 1: evict fast, 0: normal

void InitReplacementState() {
    for (auto& set : sets) {
        set.rrip.assign(LLC_WAYS, RRIP_MAX);
        set.tags.assign(LLC_WAYS, 0);
        set.valid.assign(LLC_WAYS, false);
        set.access_signature = 0;
        set.last_block = 0xFF;
        set.reuse_type = 1; // spatial by default
        set.reuse_counter = 4;
    }
    global_miss_count = 0;
    global_access_count = 0;
    global_aggressive_mode = 0;
}

// --- Victim Selection (SRRIP) ---
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

// --- Per-set Signature-based Classifier ---
void UpdateSetSignature(SetState& s, uint64_t curr_addr, uint8_t way, bool hit) {
    // Block index in set
    uint8_t block_idx = way;
    // Update signature: shift left, set bit for accessed block
    s.access_signature <<= 1;
    s.access_signature |= (1 << (block_idx & 0x7));
    // Detect reuse type:
    // - Temporal: same block accessed repeatedly (signature has repeated bits)
    // - Spatial: signature has runs of adjacent bits set (e.g., 0b11100000)
    // - Streaming: signature is sparse/random, few bits set

    // Count bits set
    uint8_t bits = s.access_signature;
    int set_count = 0;
    for (int i = 0; i < 8; i++) set_count += ((bits >> i) & 1);

    // Detect runs
    int run_len = 0, max_run = 0;
    for (int i = 0; i < 8; i++) {
        if ((bits >> i) & 1) run_len++;
        else run_len = 0;
        if (run_len > max_run) max_run = run_len;
    }

    // Heuristic:
    // - Temporal: set_count <= 2, max_run == 1 (same block)
    // - Spatial: set_count >= 4 && max_run >= 3
    // - Streaming: set_count >= 5 && max_run <= 2

    if (set_count <= 2 && max_run == 1) {
        // Temporal
        if (s.reuse_counter < 7) s.reuse_counter++;
    } else if (set_count >= 4 && max_run >= 3) {
        // Spatial
        if (s.reuse_counter < 7) s.reuse_counter++;
    } else if (set_count >= 5 && max_run <= 2) {
        // Streaming
        if (s.reuse_counter > 0) s.reuse_counter--;
    }

    // Assign reuse type
    if (s.reuse_counter <= 2) s.reuse_type = 0;      // streaming
    else if (set_count >= 4 && max_run >= 3) s.reuse_type = 1; // spatial
    else s.reuse_type = 2;                           // temporal

    s.last_block = block_idx;
}

// --- Global Aggressive Mode ---
void UpdateGlobalAggressive(bool miss) {
    global_access_count++;
    if (miss) global_miss_count++;
    if (global_access_count >= 2048) {
        // If miss rate > 55%, enable aggressive mode for next period
        if (global_miss_count * 100 / global_access_count > 55)
            global_aggressive_mode = 1;
        else
            global_aggressive_mode = 0;
        global_access_count = 0;
        global_miss_count = 0;
    }
}

// --- Replacement State Update ---
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

    // Update signature
    UpdateSetSignature(s, line_addr, way, hit);
    UpdateGlobalAggressive(!hit);

    // On hit: promote
    if (hit) {
        s.rrip[way] = RRIP_SHORT;
        s.tags[way] = line_addr;
        s.valid[way] = true;
        return;
    }

    // On miss: insertion policy
    uint8_t ins_rrip = RRIP_SHORT;
    if (global_aggressive_mode) {
        ins_rrip = RRIP_LONG; // Evict fast during miss spike
    } else {
        if (s.reuse_type == 0)      ins_rrip = RRIP_LONG; // streaming
        else if (s.reuse_type == 1) ins_rrip = RRIP_MID;  // spatial
        else                        ins_rrip = RRIP_SHORT; // temporal
    }
    s.rrip[way] = ins_rrip;
    s.tags[way] = line_addr;
    s.valid[way] = true;
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "ASDIP: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}