#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRPV parameters
static const uint8_t  MAX_RRPV     = 3;  // 2-bit RRPV [0..3]

// Dead-block counters
static const uint8_t  DB_MAX       = 3;  // 2-bit [0..3]

// SHiP PC signature
static const uint32_t SIG_BITS     = 10;
static const uint32_t SIG_TABLE_SZ = (1 << SIG_BITS);
static const uint8_t  SIG_MAX      = 3;  // 2-bit [0..3]
static const uint8_t  SIG_INIT     = 1;  // neutral start
static uint8_t        SigTable[SIG_TABLE_SZ];

// DIP set-dueling parameters
static const uint32_t DUELERS      = 64;
static const uint32_t LEADER_QUOTA = 32;
static const uint16_t PSEL_MAX     = 1023; // 10-bit
static const uint16_t PSEL_INIT    = PSEL_MAX/2;
static uint16_t       PSEL;
static uint8_t        isBIPleader[LLC_SETS];
static uint8_t        isLRUleader[LLC_SETS];

// Per-line metadata
static uint8_t        RRPV[LLC_SETS][LLC_WAYS];
static uint8_t        DB_ctr[LLC_SETS][LLC_WAYS];

// Simple PC hash
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    // Initialize per-line RRPV and dead-block counters
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w]   = MAX_RRPV;
            DB_ctr[s][w] = 0;
        }
        // Assign DIP leader sets
        uint32_t slot = s & (DUELERS - 1);
        isBIPleader[s] = (slot < LEADER_QUOTA);
        isLRUleader[s] = (slot >= LEADER_QUOTA && slot < 2*LEADER_QUOTA);
    }
    // Initialize SHiP signature table
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_INIT;
    }
    // Initialize PSEL
    PSEL = PSEL_INIT;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // 1) Evict a dead block first
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV && DB_ctr[set][w] == 0) {
            return w;
        }
    }
    // 2) Evict any at MAX_RRPV
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV) {
            return w;
        }
    }
    // 3) Age all and retry
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] < MAX_RRPV) {
            RRPV[set][w]++;
        }
    }
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
        // Promote on hit
        RRPV[set][way]   = 0;
        DB_ctr[set][way] = DB_MAX;
        if (SigTable[sig] < SIG_MAX) {
            SigTable[sig]++;
        }
        return;
    }

    // MISS --------------------------------------------------------
    // 1) DIP leader feedback
    if (isBIPleader[set]) {
        // BIP leader miss => BIP too strong => favor LRU
        if (PSEL < PSEL_MAX) PSEL++;
    } else if (isLRUleader[set]) {
        // LRU leader miss => LRU too strong => favor BIP
        if (PSEL > 0) PSEL--;
    }
    // 2) Update signature toward cold
    if (SigTable[sig] > 0) {
        SigTable[sig]--;
    }

    // 3) Decide insertion
    if (SigTable[sig] == 0) {
        // Cold PC: bypass
        RRPV[set][way]   = MAX_RRPV;
        DB_ctr[set][way] = 0;
    }
    else if (SigTable[sig] == SIG_MAX) {
        // Hot PC: MRU insert
        RRPV[set][way]   = 0;
        DB_ctr[set][way] = DB_MAX;
    }
    else {
        // Medium PC: follow DIP policy
        bool useLRU = (PSEL >= (PSEL_MAX/2));
        if (useLRU) {
            // LRU insertion (MRU)
            RRPV[set][way]   = 0;
        } else {
            // BIP insertion (distant)
            RRPV[set][way]   = MAX_RRPV;
        }
        DB_ctr[set][way] = DB_MAX;
    }
}

void PrintStats() {
    // No additional stats for now
}

void PrintStats_Heartbeat() {
    // No-op
}