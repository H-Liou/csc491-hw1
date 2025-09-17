#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters for BIP
static const uint8_t  MAX_RRPV       = 3;     // 2-bit RRPV => [0..3]
static const uint8_t  BIP_RRPV       = MAX_RRPV;  // deep insertion for BIP

// DIP set-dueling
static const uint32_t DUELERS        = 64;    // # of leader sets
static const uint32_t LEADER_QUOTA   = 32;    // each policy gets 32 leaders
static const uint16_t PSEL_MAX       = 1023;  // 10-bit saturating counter
static const uint16_t PSEL_INIT      = PSEL_MAX/2;
static uint16_t       PSEL;
static uint8_t        isLRULeader[LLC_SETS];
static uint8_t        isBIPLeader[LLC_SETS];

// SHiP-lite signature table
static const uint32_t SIG_BITS       = 10;
static const uint32_t SIG_TABLE_SZ   = (1 << SIG_BITS);
static const uint8_t  SIG_MAX        = 3;     // 2-bit counter => [0..3]
static uint8_t        SigTable[SIG_TABLE_SZ];

// Dead-block counters (2-bit each)
static const uint8_t  DB_MAX         = 3;
static uint8_t        DB_ctr[LLC_SETS][LLC_WAYS];

// Per-line RRPV
static uint8_t        RRPV[LLC_SETS][LLC_WAYS];

// Simple PC hash
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    // Initialize RRPV and dead-block counters
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w]   = MAX_RRPV;
            DB_ctr[s][w] = 0;
        }
    }
    // Initialize SHiP signatures to weakly unused
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_MAX/2;
    }
    // Initialize PSEL and leader sets
    PSEL = PSEL_INIT;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        uint32_t slot = s & (DUELERS - 1);
        isLRULeader[s] = (slot < LEADER_QUOTA);
        isBIPLeader[s] = (slot >= LEADER_QUOTA && slot < 2*LEADER_QUOTA);
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // 1) Prefer dead blocks at max RRPV
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV && DB_ctr[set][w] == 0) {
            return w;
        }
    }
    // 2) Then any block at max RRPV
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV) {
            return w;
        }
    }
    // 3) Otherwise age everyone with RRPV < MAX_RRPV
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] < MAX_RRPV) {
            RRPV[set][w]++;
        }
    }
    // Retry
    return GetVictimInSet(cpu, set, current_set, PC, paddr, type);
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
    uint32_t sig = PCIndex(PC, SIG_TABLE_SZ - 1);

    if (hit) {
        // On hit: promote to MRU, train SHiP, refresh dead-block counter
        RRPV[set][way]   = 0;
        if (SigTable[sig] < SIG_MAX) SigTable[sig]++;
        DB_ctr[set][way] = DB_MAX;
        return;
    }

    // MISS --------------------------------------------------------
    // 1) Leader set updates for DIP
    if (isLRULeader[set]) {
        // LRU leader miss => LRU is poor => favor BIP
        if (PSEL > 0) PSEL--;
    } else if (isBIPLeader[set]) {
        // BIP leader miss => BIP is poor => favor LRU
        if (PSEL < PSEL_MAX) PSEL++;
    }

    // 2) Decide policy
    bool useLRU = (PSEL > (PSEL_MAX / 2));

    // 3) Final insertion decision
    bool hotPC = (SigTable[sig] > (SIG_MAX/2));
    if (hotPC || useLRU) {
        // Hot loop or LRU policy: immediate MRU
        RRPV[set][way] = 0;
    } else {
        // BIP policy: deep insert, 1/32 chance of MRU
        if (PCIndex(PC, 31) == 0) {
            RRPV[set][way] = 0;
        } else {
            RRPV[set][way] = BIP_RRPV;
        }
    }
    // New block starts with fresh dead-block budget
    DB_ctr[set][way] = DB_MAX;
}

void PrintStats() {
    // No additional stats for now
}

void PrintStats_Heartbeat() {
    // No-op
}