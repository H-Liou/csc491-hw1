#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Replacement state per block ---
struct BlockState {
    uint32_t reuse_dist;     // Estimated reuse distance (lower is better)
    uint16_t signature;      // Hash of PC and block address
    uint8_t  freq;           // Frequency counter
    uint64_t last_access;    // For recency and tie-breaking
};

std::vector<std::vector<BlockState>> block_state(LLC_SETS, std::vector<BlockState>(LLC_WAYS));

// --- Per-set adaptive weights and stats ---
struct SetStats {
    uint32_t recent_hits;
    uint32_t recent_misses;
    uint32_t freq_hits;
    uint32_t reuse_hits;
    uint32_t sig_hits;
    uint8_t  phase_mode;        // 0: regular, 1: irregular
    float    recency_weight;
    float    freq_weight;
    float    reuse_weight;
    float    sig_weight;
    uint64_t last_phase_update;
};

std::vector<SetStats> set_stats(LLC_SETS);

// --- Global stats ---
uint64_t global_access_counter = 0;
uint64_t total_evictions = 0;

// --- Utility: signature hash ---
inline uint16_t sig_hash(uint64_t PC, uint64_t addr) {
    // Mix PC and block address for correlation
    return (uint16_t)((PC ^ (addr >> 6)) & 0xFFFF);
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_state[set][way] = {LLC_WAYS, 0, 0, 0};
        }
        set_stats[set] = {0, 0, 0, 0, 0, 0, 0.5f, 0.2f, 0.2f, 0.1f, 0};
    }
    global_access_counter = 0;
    total_evictions = 0;
}

// --- Find victim in the set ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    global_access_counter++;

    // Update phase weights every 4096 accesses per set
    SetStats& ss = set_stats[set];
    if (global_access_counter - ss.last_phase_update > 4096) {
        // If reuse hits dominate, favor reuse distance
        if (ss.reuse_hits > ss.freq_hits && ss.reuse_hits > ss.sig_hits) {
            ss.recency_weight = 0.2f;
            ss.freq_weight = 0.2f;
            ss.reuse_weight = 0.5f;
            ss.sig_weight = 0.1f;
            ss.phase_mode = 0; // Regular
        }
        // If signature hits dominate, favor signature correlation
        else if (ss.sig_hits > ss.freq_hits && ss.sig_hits > ss.reuse_hits) {
            ss.recency_weight = 0.2f;
            ss.freq_weight = 0.1f;
            ss.reuse_weight = 0.2f;
            ss.sig_weight = 0.5f;
            ss.phase_mode = 0; // Regular
        }
        // If frequency hits dominate, favor frequency
        else if (ss.freq_hits > ss.reuse_hits && ss.freq_hits > ss.sig_hits) {
            ss.recency_weight = 0.2f;
            ss.freq_weight = 0.5f;
            ss.reuse_weight = 0.2f;
            ss.sig_weight = 0.1f;
            ss.phase_mode = 0; // Regular
        }
        // Otherwise, favor recency (irregular phase)
        else {
            ss.recency_weight = 0.7f;
            ss.freq_weight = 0.2f;
            ss.reuse_weight = 0.05f;
            ss.sig_weight = 0.05f;
            ss.phase_mode = 1; // Irregular
        }
        // Reset stats for next window
        ss.freq_hits = ss.reuse_hits = ss.sig_hits = 0;
        ss.last_phase_update = global_access_counter;
    }

    // Compute scores for all blocks
    float min_score = 1e9;
    int victim_way = 0;
    uint16_t curr_sig = sig_hash(PC, paddr);

    for (int way = 0; way < LLC_WAYS; ++way) {
        BlockState& bs = block_state[set][way];

        // Recency: older blocks are less likely to be reused
        float recency_score = (float)(global_access_counter - bs.last_access) / 4096.0f;

        // Frequency: lower frequency is less likely to be reused
        float freq_score = 1.0f - ((float)bs.freq / 15.0f);

        // Reuse distance: higher reuse distance is bad
        float reuse_score = (float)bs.reuse_dist / LLC_WAYS;

        // Signature: blocks not matching current signature are penalized
        float sig_score = (bs.signature == curr_sig) ? 0.0f : 1.0f;

        // Weighted sum
        float score = ss.recency_weight * recency_score +
                      ss.freq_weight * freq_score +
                      ss.reuse_weight * reuse_score +
                      ss.sig_weight * sig_score;

        if (score < min_score) {
            min_score = score;
            victim_way = way;
        }
    }
    total_evictions++;
    return victim_way;
}

// --- Update replacement state ---
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
    global_access_counter++;
    BlockState& bs = block_state[set][way];
    SetStats& ss = set_stats[set];

    // Update reuse distance: reset on hit, increment on miss
    if (hit)
        bs.reuse_dist = 0;
    else
        bs.reuse_dist = std::min(bs.reuse_dist + 1, LLC_WAYS);

    // Update frequency counter
    if (hit)
        bs.freq = std::min(bs.freq + 1, 15u);
    else
        bs.freq = bs.freq / 2;

    // Update signature
    uint16_t curr_sig = sig_hash(PC, paddr);
    bs.signature = curr_sig;

    // Update last access time
    bs.last_access = global_access_counter;

    // Update set-level stats for phase detection
    if (hit) {
        ss.recent_hits++;
        if (bs.freq > 8)
            ss.freq_hits++;
        if (bs.reuse_dist == 0)
            ss.reuse_hits++;
        if (bs.signature == curr_sig)
            ss.sig_hits++;
    } else {
        ss.recent_misses++;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "MFDRR: total_evictions=" << total_evictions << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    PrintStats();
}