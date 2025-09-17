#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Policy Parameters ---
constexpr int REUSE_MAX = 7;              // Max reuse counter per line
constexpr int MISS_WINDOW = 128;          // Window for set-level miss/hit tracking
constexpr int MISS_THRESHOLD = 32;        // If misses in window exceed this, treat as irregular
constexpr int DECAY_INTERVAL = 1024;      // How often to decay reuse counters

struct LineState {
    uint16_t signature;       // Compact signature: hash of PC and block address
    uint8_t reuse_counter;    // Reuse counter (0..REUSE_MAX)
    bool spatial_locality;    // True if recent access was spatially adjacent
};

struct SetState {
    uint32_t window_hits;
    uint32_t window_misses;
    uint32_t last_decay_time;
    bool prefer_signature;    // If true, evict by signature/reuse, else by LRU
    uint16_t last_signature;  // Last accessed signature for spatial locality
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;
uint32_t global_time = 0;

// Telemetry
uint64_t total_evictions = 0;
uint64_t sig_evictions = 0;
uint64_t lru_evictions = 0;
std::array<uint64_t, LLC_SETS> set_sig_evictions = {};

static inline uint16_t gen_signature(uint64_t PC, uint64_t paddr) {
    // Simple hash: combine PC and block address, CRC for mixing
    return (champsim_crc2(PC, paddr) & 0xFFFF);
}

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way] = {0, 0, false};
        }
        set_states[set] = {};
        set_states[set].window_hits = 0;
        set_states[set].window_misses = 0;
        set_states[set].last_decay_time = 0;
        set_states[set].prefer_signature = false;
        set_states[set].last_signature = 0;
    }
    global_time = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    global_time++;

    auto& sstate = set_states[set];
    // Adaptive filtering: prefer signature-based eviction if recent miss rate is high
    if ((sstate.window_misses + sstate.window_hits) >= MISS_WINDOW) {
        if (sstate.window_misses > MISS_THRESHOLD) {
            sstate.prefer_signature = true;
        } else {
            sstate.prefer_signature = false;
        }
        sstate.window_hits = 0;
        sstate.window_misses = 0;
    }

    uint16_t curr_sig = gen_signature(PC, paddr);
    int victim = -1;

    if (sstate.prefer_signature) {
        // Signature-based eviction: find line with lowest reuse and mismatched signature
        uint8_t min_reuse = REUSE_MAX+1;
        bool found = false;
        for (int way = 0; way < LLC_WAYS; ++way) {
            auto& line = line_states[set][way];
            // Prefer lines with mismatched signature and low reuse (phase change or irregular)
            bool sig_mismatch = (line.signature != curr_sig);
            if ((line.reuse_counter < min_reuse && sig_mismatch) ||
                (!found && sig_mismatch)) {
                min_reuse = line.reuse_counter;
                victim = way;
                found = true;
            }
        }
        // If all signatures match, evict lowest reuse
        if (!found) {
            min_reuse = REUSE_MAX+1;
            for (int way = 0; way < LLC_WAYS; ++way) {
                if (line_states[set][way].reuse_counter < min_reuse) {
                    min_reuse = line_states[set][way].reuse_counter;
                    victim = way;
                }
            }
        }
        sig_evictions++;
        set_sig_evictions[set]++;
    } else {
        // LRU eviction with spatial locality boost
        // Retain lines with spatial locality if possible
        int lru_candidate = -1;
        uint8_t min_reuse = REUSE_MAX+1;
        for (int way = 0; way < LLC_WAYS; ++way) {
            auto& line = line_states[set][way];
            if (!line.spatial_locality) {
                if (line.reuse_counter < min_reuse) {
                    min_reuse = line.reuse_counter;
                    lru_candidate = way;
                }
            }
        }
        if (lru_candidate >= 0) {
            victim = lru_candidate;
        } else {
            // If all have spatial locality, evict lowest reuse
            min_reuse = REUSE_MAX+1;
            for (int way = 0; way < LLC_WAYS; ++way) {
                if (line_states[set][way].reuse_counter < min_reuse) {
                    min_reuse = line_states[set][way].reuse_counter;
                    victim = way;
                }
            }
        }
        lru_evictions++;
    }
    total_evictions++;
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
    global_time++;
    auto& sstate = set_states[set];
    auto& line = line_states[set][way];

    // --- Window miss/hit tracking ---
    if (hit) sstate.window_hits++;
    else     sstate.window_misses++;

    // --- Signature and reuse update ---
    uint16_t curr_sig = gen_signature(PC, paddr);
    if (hit) {
        line.reuse_counter = std::min(REUSE_MAX, line.reuse_counter + 1);
    } else {
        line.reuse_counter = std::max(0, line.reuse_counter - 1);
    }
    line.signature = curr_sig;

    // --- Spatial locality detection ---
    // If current signature is adjacent to previous, set spatial locality
    if (std::abs((int)curr_sig - (int)sstate.last_signature) <= 2) {
        line.spatial_locality = true;
    } else {
        line.spatial_locality = false;
    }
    sstate.last_signature = curr_sig;

    // --- Periodic reuse decay ---
    if (global_time - sstate.last_decay_time > DECAY_INTERVAL) {
        for (int w = 0; w < LLC_WAYS; ++w) {
            line_states[set][w].reuse_counter = std::max(0, line_states[set][w].reuse_counter - 1);
        }
        sstate.last_decay_time = global_time;
    }
}

void PrintStats() {
    std::cout << "SDRSL: Total evictions: " << total_evictions << std::endl;
    std::cout << "SDRSL: Signature-based evictions: " << sig_evictions << std::endl;
    std::cout << "SDRSL: LRU-based evictions: " << lru_evictions << std::endl;
    std::cout << "SDRSL: Sets using signature-based eviction (nonzero): ";
    int cnt = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set_sig_evictions[set] > 0) {
            std::cout << "[" << set << "]=" << set_sig_evictions[set] << " ";
            cnt++;
            if (cnt > 20) { std::cout << "..."; break; }
        }
    }
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "SDRSL heartbeat: evictions=" << total_evictions
              << " sig_evictions=" << sig_evictions
              << " lru_evictions=" << lru_evictions << std::endl;
}