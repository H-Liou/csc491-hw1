#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRIP parameters
static const uint8_t RRPV_MAX    = 3;   // 2‐bit [0..3]
static const uint8_t RRPV_INIT_S = 2;   // SRRIP insertion (short)
static const uint8_t RRPV_INIT_B = 3;   // BRRIP insertion (long)

// SHiP parameters
static const uint32_t SHCT_BITS   = 14;
static const uint32_t SHCT_SIZE   = (1 << SHCT_BITS);
static const uint8_t  SHCT_CTR_MAX= 3;
static const uint8_t  SHCT_INIT    = 2;

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
static uint64_t stat_hits    = 0;
static uint64_t stat_misses  = 0;
static uint64_t stat_evictions=0;

// Helpers
static inline uint32_t MakeSignature(uint64_t PC, uint64_t paddr) {
    // combine PC and block address bits for hashing
    uint64_t tag = paddr >> 12;
    uint32_t sig = (uint32_t)((PC ^ tag) & (SHCT_SIZE - 1));
    return sig;
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
    }
    // Reset stats
    stat_hits     = 0;
    stat_misses   = 0;
    stat_evictions= 0;
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
        // look for RRPV == max
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (ReplState[set][w].rrpv == RRPV_MAX) {
                return w;
            }
        }
        // age all
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
    if (hit) {
        // Hit: promote and update SHCT
        stat_hits++;
        BlockInfo &blk = ReplState[set][way];
        blk.rrpv = 0;
        if (!blk.reused) {
            // first promotion counts as reuse
            blk.reused = true;
            uint32_t sig = blk.signature;
            if (SHCT[sig] < SHCT_CTR_MAX) {
                SHCT[sig]++;
            }
        }
    } else {
        // Miss: allocate a victim
        stat_misses++;
        uint32_t victim = GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
        // On eviction, if never reused, decrement its SHCT counter
        BlockInfo &old_blk = ReplState[set][victim];
        if (!old_blk.reused) {
            stat_evictions++;
            uint32_t old_sig = old_blk.signature;
            if (SHCT[old_sig] > 0) {
                SHCT[old_sig]--;
            }
        }
        // Decide insertion policy using SHCT
        uint32_t sig = MakeSignature(PC, paddr);
        uint8_t ctr = SHCT[sig];
        bool predict_reuse = (ctr > 0);
        // Fill the new block
        old_blk.signature = sig;
        old_blk.reused    = false;
        old_blk.rrpv      = predict_reuse ? RRPV_INIT_S
                                          : RRPV_INIT_B;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint64_t total = stat_hits + stat_misses;
    double hit_rate = total ? (100.0 * stat_hits / total) : 0.0;
    std::cout << "---- SHiP-RRIP Replacement Stats ----\n";
    std::cout << "Total Accesses: " << total << "\n";
    std::cout << "Hits: " << stat_hits
              << "  Misses: " << stat_misses
              << "  Hit Rate: " << hit_rate << "%\n";
    std::cout << "Evictions without reuse: " << stat_evictions << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}