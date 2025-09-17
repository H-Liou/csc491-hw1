#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Per-block metadata
struct BlockMeta {
    uint64_t lru_counter;    // Recency
    uint64_t freq_counter;   // Frequency
    uint64_t last_pc;        // Last access PC
    uint64_t last_access;    // Timestamp
};

std::array<std::array<BlockMeta, LLC_WAYS>, LLC_SETS> block_state;
uint64_t global_timestamp = 0;

// Per-set recent miss/hit tracking for phase adaptation
std::array<uint32_t, LLC_SETS> recent_hits = {};
std::array<uint32_t, LLC_SETS> recent_misses = {};

// PC-based future reuse prediction (simple)
std::unordered_map<uint64_t, uint32_t> pc_reuse_hint; // PC -> expected reuse

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_state[set][way] = {way, 0, 0, 0};
        }
        recent_hits[set] = 0;
        recent_misses[set] = 0;
    }
    pc_reuse_hint.clear();
    global_timestamp = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Phase detection: if hits > misses in recent accesses, prefer LRU; else, prefer LFU+reuse
    bool prefer_lru = recent_hits[set] > recent_misses[set];

    // For each way, compute a score: lower score = better victim
    uint32_t victim = 0;
    uint64_t best_score = UINT64_MAX;
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        const BlockMeta &meta = block_state[set][way];

        // If block is invalid, evict immediately
        if (current_set[way].valid == false)
            return way;

        // PC reuse hint: if block's last PC matches current PC and hint is high, avoid eviction
        uint32_t pc_hint = pc_reuse_hint[meta.last_pc];
        uint64_t score = 0;

        if (prefer_lru) {
            // LRU with slight penalty for high frequency
            score = meta.lru_counter + (meta.freq_counter > 2 ? LLC_WAYS : 0) + (pc_hint > 2 ? LLC_WAYS : 0);
        } else {
            // Frequency + reuse prediction
            score = (meta.freq_counter < 2 ? 0 : LLC_WAYS) + meta.lru_counter + (pc_hint > 2 ? LLC_WAYS : 0);
        }

        // Prefer blocks with oldest timestamp if scores tie (Belady-like)
        if (score < best_score ||
            (score == best_score && meta.last_access < block_state[set][victim].last_access)) {
            best_score = score;
            victim = way;
        }
    }
    return victim;
}

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
    global_timestamp++;

    // Update hit/miss counters for phase adaptation
    if (hit)
        recent_hits[set]++;
    else
        recent_misses[set]++;

    // Decay counters periodically to avoid stale phase
    if ((recent_hits[set] + recent_misses[set]) > 128) {
        recent_hits[set] /= 2;
        recent_misses[set] /= 2;
    }

    // Update block metadata
    BlockMeta &meta = block_state[set][way];
    meta.lru_counter = 0; // Most recently used
    meta.freq_counter = std::min(meta.freq_counter + 1, 255u); // Saturate
    meta.last_pc = PC;
    meta.last_access = global_timestamp;

    // Update PC reuse hint (simple: count accesses per PC)
    pc_reuse_hint[PC] = std::min(pc_reuse_hint[PC] + 1, 8u);

    // Age other blocks in set
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (w == way) continue;
        block_state[set][w].lru_counter++;
        // Decay frequency for blocks not accessed
        if (block_state[set][w].freq_counter > 0)
            block_state[set][w].freq_counter--;
    }
}

void PrintStats() {
    // Optional: print PC reuse histogram, phase adaptation stats
    std::cout << "AHLB: Adaptive Hybrid LRU-Belady Replacement statistics\n";
}

void PrintStats_Heartbeat() {
    // Optional: print periodic stats
}