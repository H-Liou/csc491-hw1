#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters
static const uint8_t RRPV_MAX     = 3;   // 2‐bit [0..3]
static const uint8_t RRPV_INIT_S  = 2;   // SRRIP insertion (short)
static const uint8_t RRPV_INIT_B  = 3;   // BRRIP insertion (long)

// SHiP parameters
static const uint32_t SHCT_BITS    = 14;
static const uint32_t SHCT_SIZE    = (1 << SHCT_BITS);
static const uint8_t  SHCT_CTR_MAX = 3;
static const uint8_t  SHCT_INIT    = 2;

// Miss Counter Table (for bypass)
static const uint8_t  MCT_CTR_MAX  = 3;
static const uint8_t  MCT_BYPASS_TH= 2;
static uint8_t MCT[SHCT_SIZE];

// Signature History Counter Table
static uint8_t SHCT[SHCT_SIZE];

// Replacement state per line
struct BlockInfo {
    uint8_t  rrpv;
    uint32_t signature;
    bool     reused;
};
static BlockInfo ReplState[LLC_SETS][LLC_WAYS];

// Statistics
static uint64_t stat_hits       = 0;
static uint64_t stat_misses     = 0;
static uint64_t stat_evictions  = 0;
static uint64_t stat_bypasses   = 0;

// Helpers
static inline uint32_t MakeSignature(uint64_t PC, uint64_t paddr) {
    uint64_t tag = paddr >> 12;
    return (uint32_t)((PC ^ tag) & (SHCT_SIZE - 1));
}

// Initialize replacement state
void InitReplacementState() {
    // Initialize RRIP state
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            ReplState[s][w].rrpv      = RRPV_MAX;
            ReplState[s][w].signature = 0;
            ReplState[s][w].reused    = false;
        }
    }
    // Initialize SHCT
    for (uint32_t i = 0; i < SHCT_SIZE; i++) {
        SHCT[i] = SHCT_INIT;
        MCT[i]  = 0;
    }
    // Reset stats
    stat_hits      = 0;
    stat_misses    = 0;
    stat_evictions = 0;
    stat_bypasses  = 0;
}

// Find victim in the set using RRIP aging
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (ReplState[set][w].rrpv == RRPV_MAX) {
                return w;
            }
        }
        // Age all if none at max
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (ReplState[set][w].rrpv < RRPV_MAX) {
                ReplState[set][w].rrpv++;
            }
        }
    }
}

// Update replacement state on access
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
    uint32_t sig = MakeSignature(PC, paddr);
    if (hit) {
        // Hit processing
        stat_hits++;
        BlockInfo &blk = ReplState[set][way];
        blk.rrpv = 0;
        if (!blk.reused) {
            blk.reused = true;
            if (SHCT[sig] < SHCT_CTR_MAX) {
                SHCT[sig]++;
            }
        }
        // Set‐based promotion: capture spatial locality
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (w != way && ReplState[set][w].rrpv > 0) {
                ReplState[set][w].rrpv--;
            }
        }
        // On a reuse, reset bypass counter
        MCT[sig] = 0;
    } else {
        // Miss processing
        stat_misses++;
        // Bypass decision
        bool bypass = false;
        if (SHCT[sig] == 0) {
            // no predicted reuse → count misses
            if (MCT[sig] < MCT_CTR_MAX) {
                MCT[sig]++;
            }
            if (MCT[sig] > MCT_BYPASS_TH) {
                bypass = true;
            }
        }
        if (bypass) {
            stat_bypasses++;
            return;
        }
        // allocate victim
        uint32_t victim = GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
        // on eviction of never‐reused block, penalize SHCT
        BlockInfo &old_blk = ReplState[set][victim];
        if (!old_blk.reused) {
            stat_evictions++;
            uint32_t old_sig = old_blk.signature;
            if (SHCT[old_sig] > 0) {
                SHCT[old_sig]--;
            }
        }
        // decide insertion
        uint8_t ctr = SHCT[sig];
        bool predict_reuse = (ctr > 0);
        // fill new
        old_blk.signature = sig;
        old_blk.reused    = false;
        old_blk.rrpv      = predict_reuse ? RRPV_INIT_S
                                          : RRPV_INIT_B;
        // reset bypass counter on insertion
        MCT[sig] = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint64_t total = stat_hits + stat_misses;
    double hit_rate = total ? (100.0 * stat_hits / total) : 0.0;
    std::cout << "---- SHiP-MSP Replacement Stats ----\n";
    std::cout << "Total Accesses:        " << total        << "\n";
    std::cout << "Hits:                  " << stat_hits    << "\n";
    std::cout << "Misses:                " << stat_misses  << "\n";
    std::cout << "Hit Rate:              " << hit_rate << "%\n";
    std::cout << "Evictions without reuse:" << stat_evictions << "\n";
    std::cout << "Bypassed Allocations:  " << stat_bypasses  << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}