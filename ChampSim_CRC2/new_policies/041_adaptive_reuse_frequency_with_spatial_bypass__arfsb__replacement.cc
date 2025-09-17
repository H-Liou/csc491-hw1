#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

#define MAX_RRPV 3
#define INSERT_RRPV 2
#define MAX_FREQ 7
#define SPATIAL_WINDOW 4 // Number of blocks to check for spatial locality

struct ARFSB_BlockMeta {
    uint8_t valid;
    uint64_t tag;
    uint8_t rrpv;
    uint8_t freq;      // Frequency counter (0-7)
    uint8_t spatial;   // Spatial locality flag (0/1)
};

struct ARFSB_SetState {
    std::vector<ARFSB_BlockMeta> meta;
};

// Per-set state
std::vector<ARFSB_SetState> sets(LLC_SETS);

// Global adaptive thresholds
uint8_t adaptive_bypass_threshold = 1; // If freq <= this, bypass
uint8_t adaptive_spatial_threshold = 1; // If spatial == 0, bypass

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, MAX_RRPV, 0, 0});
    }
    adaptive_bypass_threshold = 1;
    adaptive_spatial_threshold = 1;
}

// --- Helper: check spatial locality in set ---
bool check_spatial_locality(uint32_t set, uint64_t tag) {
    // Check if nearby blocks in the set have similar tags (spatial locality)
    ARFSB_SetState& s = sets[set];
    int count = 0;
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (s.meta[way].valid) {
            uint64_t block_tag = s.meta[way].tag;
            if (std::abs((int64_t)tag - (int64_t)block_tag) <= SPATIAL_WINDOW)
                count++;
        }
    }
    return count > 0;
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
    ARFSB_SetState& s = sets[set];

    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (!current_set[way].valid)
            return way;
    }

    // Find block with RRPV == MAX_RRPV, prefer freq==0 (cold blocks)
    uint32_t victim = LLC_WAYS;
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (s.meta[way].rrpv == MAX_RRPV) {
            if (victim == LLC_WAYS || s.meta[way].freq < s.meta[victim].freq)
                victim = way;
        }
    }
    if (victim != LLC_WAYS)
        return victim;

    // If none, increment all RRPVs and try again
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        s.meta[way].rrpv = std::min<uint8_t>(MAX_RRPV, s.meta[way].rrpv + 1);
    // Recursive call is safe: will terminate
    return GetVictimInSet(cpu, set, current_set, PC, paddr, type);
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
    ARFSB_SetState& s = sets[set];
    uint64_t tag = paddr >> 6;

    if (hit) {
        // On hit: promote block, increment frequency, mark spatial
        s.meta[way].rrpv = 0;
        s.meta[way].freq = std::min<uint8_t>(MAX_FREQ, s.meta[way].freq + 1);
        s.meta[way].spatial = check_spatial_locality(set, tag) ? 1 : 0;
    } else {
        // On fill: check whether to bypass based on frequency and spatial locality
        bool spatial = check_spatial_locality(set, tag);
        uint8_t freq = 1; // New block starts with freq=1

        // Bypass if predicted low reuse and low spatial locality
        if (freq <= adaptive_bypass_threshold && !spatial) {
            // Do not cache this block (simulate bypass by marking invalid)
            s.meta[way].valid = 0;
            s.meta[way].tag = 0;
            s.meta[way].rrpv = MAX_RRPV;
            s.meta[way].freq = 0;
            s.meta[way].spatial = 0;
            return;
        }

        // Otherwise, insert normally
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].freq = freq;
        s.meta[way].spatial = spatial ? 1 : 0;
        // Insert RRPV: retain longer if spatial locality detected
        s.meta[way].rrpv = spatial ? INSERT_RRPV : MAX_RRPV;

        // On eviction: adapt thresholds based on victim's freq/spatial
        if (victim_addr != 0) {
            uint64_t victim_tag = victim_addr >> 6;
            for (uint32_t i = 0; i < LLC_WAYS; ++i) {
                if (s.meta[i].valid && s.meta[i].tag == victim_tag) {
                    // If block was not reused, increase bypass threshold
                    if (s.meta[i].freq <= 1)
                        adaptive_bypass_threshold = std::min<uint8_t>(MAX_FREQ, adaptive_bypass_threshold + 1);
                    // If block had spatial locality but no reuse, increase spatial threshold
                    if (s.meta[i].spatial && s.meta[i].freq <= 1)
                        adaptive_spatial_threshold = std::min<uint8_t>(MAX_FREQ, adaptive_spatial_threshold + 1);
                    break;
                }
            }
        }
    }
}

// --- Stats ---
void PrintStats() {
    uint64_t total_hits = 0, total_misses = 0, total_bypassed = 0;
    for (const auto& set : sets) {
        for (const auto& block : set.meta) {
            if (block.valid)
                total_hits += block.freq - 1;
            total_misses += block.valid ? 1 : 0;
            if (!block.valid)
                total_bypassed++;
        }
    }
    double hitrate = (total_hits * 100.0) / (total_hits + total_misses + 1e-5);
    std::cout << "ARFSB: Hits=" << total_hits << " Misses=" << total_misses
              << " Bypassed=" << total_bypassed
              << " HitRate=" << hitrate << "%" << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}