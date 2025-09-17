#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRIP parameters
static const uint8_t MAX_RRPV   = 3;
static const uint8_t INIT_RRPV  = 2;

// DIP parameters
static const uint16_t PSEL_MAX  = 1023;
static const uint16_t PSEL_INIT = 512;
static uint16_t       PSEL;
static uint8_t        DIP_leader[LLC_SETS];  // 0=LIP leader, 1=BIP leader, else follower

// SHiP-lite signature table (2-bit counters)
static const uint32_t SHCT_SIZE = 2048;
static const uint32_t SHCT_MASK = SHCT_SIZE - 1;
static uint8_t        SHCT[SHCT_SIZE];

// Dead-block approximation (2-bit counters per line)
static uint8_t DeadCtr[LLC_SETS][LLC_WAYS];

// Stride detector for streaming bypass
static const uint32_t STRIDE_SIZE = 512;
static const uint32_t STRIDE_MASK = STRIDE_SIZE - 1;
static const uint8_t  STRIDE_THRESH = 2;
static uint32_t       SD_last_blk[STRIDE_SIZE];
static int32_t        SD_last_stride[STRIDE_SIZE];
static uint8_t        SD_count[STRIDE_SIZE];

// Replacement metadata: 2-bit RRPV per line
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 12)) & mask);
}

void InitReplacementState() {
    // --- IMPLEMENT THE FUNCTION ---
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
    return 0; // replaced block index
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
}

void PrintStats() {
    // --- IMPLEMENT THE FUNCTION ---
}

void PrintStats_Heartbeat() {
    // --- IMPLEMENT THE FUNCTION ---
}