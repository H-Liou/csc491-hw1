#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE   1
#define LLC_SETS   (NUM_CORE * 2048)
#define LLC_WAYS   16

// DIP sampling parameters
static const uint32_t SAMPLE_RATIO = 32;      // one sample set per 32
static const uint32_t PSEL_MAX      = 1023;   // 10-bit saturating counter
static uint32_t       PSEL;                  // global policy selector
static uint8_t        set_policy[LLC_SETS];  // 0=follower,1=SRRIP-sample,2=BRRIP-sample

// SHiP parameters
static const uint32_t SHCT_BITS    = 14;
static const uint32_t SHCT_SIZE    = (1 << SHCT_BITS);
static const uint8_t  SHCT_INIT     = 2;
static const uint8_t  SHCT_MAX      = 3;
static const uint8_t  MCT_MAX       = 3;
static const uint8_t  MCT_TH        = 2;
static uint8_t        SHCT[SHCT_SIZE];       // signature reuse counters
static uint8_t        MCT[SHCT_SIZE];        // miss counters for bypass

// RRIP parameters
static const uint8_t RRPV_MAX     = 3;
static const uint8_t RRPV_SRRIP   = 2;
static const uint8_t RRPV_BRRIP   = 3;

// Replacement state per cache line
struct BlockInfo {
    uint8_t  rrpv;
    uint32_t signature;
    bool     reused;
};
static BlockInfo ReplState[LLC_SETS][LLC_WAYS];

// Statistics
static uint64_t stat_hits, stat_misses, stat_evictions, stat_bypasses;

// Compute a small PC+paddr signature for SHCT/MCT indexing
static inline uint32_t MakeSignature(uint64_t PC, uint64_t paddr) {
    // --- IMPLEMENT THE FUNCTION ---
    return 0;
}

// Initialize all tables, PSEL, sample‐set mapping, and RRPV
void InitReplacementState() {
    // --- IMPLEMENT THE FUNCTION ---
}

// Find a victim way by standard RRIP aging
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // --- IMPLEMENT THE FUNCTION ---
    return 0;
}

// On each access, update RRPV, SHCT/MCT, PSEL, and statistics
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
    // --- IMPLEMENT THE FUNCTION ---
}

// Report final hit/miss/bypass/eviction statistics
void PrintStats() {
    // --- IMPLEMENT THE FUNCTION ---
}

// Periodic heartbeat print (if desired)
void PrintStats_Heartbeat() {
    // --- IMPLEMENT THE FUNCTION ---
}