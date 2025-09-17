#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRIP parameters
static const uint8_t MAX_RRPV  = 3;            // 2-bit [0..3]
static const uint8_t SRRIP_INS = MAX_RRPV - 1; // =2

// SHiP-lite: PC‐signature history
static const uint32_t SHCT_SIZE = 256;         // number of signature entries
static uint8_t SHCT[SHCT_SIZE];                // 2-bit reuse counters [0..3]
static uint16_t SigIdx[LLC_SETS][LLC_WAYS];    // 8-bit signature per line

// DRRIP dueling (10-bit PSEL)
static uint16_t PSEL = SHCT_SIZE * 2;          // saturating [0..1023]
static bool    leader_srrip[LLC_SETS];         // mark SRRIP leader sets
static bool    leader_bip[LLC_SETS];           // mark BIP leader sets

// Per-line RRPV
static uint8_t RRPV[LLC_SETS][LLC_WAYS];       // 2-bit RRPV field

// Simple streaming detector
static uint64_t last_addr[NUM_CORE];           // last block address per core
static int8_t   stream_conf[NUM_CORE];         // confidence [-8..+7]

void InitReplacementState() {
    // --- IMPLEMENT THE FUNCTION ---
    // Initialize RRPV to MAX, SHCT to weakly no-reuse (1),
    // choose 64 leader sets for BIP/SRRIP, zero PSEL, clear stream detectors.
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // --- IMPLEMENT THE FUNCTION ---
    // Standard RRIP: find a way with RRPV==MAX, else increment all RRPVs and retry.
    return 0; // way to evict
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
    // --- IMPLEMENT THE FUNCTION ---
    // On hit:
    //   * RRPV = 0 (MRU)
    //   * SHCT[SigIdx]++ if <3
    //
    // On miss:
    //   1) If the evicted line never saw a hit, SHCT[old_sig]--
    //   2) Detect streaming via stride = (paddr>>6) - (last_addr>>6):
    //        if monotonic, adjust stream_conf and possibly bypass
    //   3) Update last_addr
    //   4) Dueling: if leader set, update PSEL
    //   5) Compute new SigIdx = lowbits(PC ^ (paddr>>6))
    //   6) Choose insertion RRPV:
    //        - if streaming_confident: MAX_RRPV (bypass)
    //        - else if (leader_srrip or PSEL favors SRRIP): SRRIP_INS or MRU per SHCT
    //        - else BIP: insert at MAX_RRPV-1 or per SHCT
}

void PrintStats() {
    // --- IMPLEMENT THE FUNCTION ---
    // Optionally print final PSEL, SHCT hit/miss counters, streaming stats.
}

void PrintStats_Heartbeat() {
    // --- IMPLEMENT THE FUNCTION ---
    // (Optional periodic logging)
}