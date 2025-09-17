#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters
static const uint8_t MAX_RRPV       = 3;
static const uint8_t NEUTRAL_RRPV   = (MAX_RRPV - 1);

// DIP dueling parameters
static const uint32_t DUELERS       = 64;    // 32 BIP + 32 LRU
static const uint32_t LEADER_QUOTA  = 32;
static const uint16_t PSEL_MAX      = 1023;  // 10-bit
static const uint16_t PSEL_INIT     = PSEL_MAX / 2;
static uint16_t       PSEL;
static bool           isBIPLeader[LLC_SETS];
static bool           isLRULeader[LLC_SETS];

// SHiP-lite signature table (2-bit)
static const uint32_t SIG_BITS      = 10;
static const uint32_t SIG_TABLE_SZ  = (1 << SIG_BITS);
static const uint32_t SIG_MASK      = (SIG_TABLE_SZ - 1);
static const uint8_t  SIG_MAX       = 3;
static const uint8_t  SIG_INIT      = 1;     // neutral
static uint8_t        SigTable[SIG_TABLE_SZ];

// Dead-block approximation (2-bit per line)
static const uint8_t  DB_MAX        = 3;
static uint8_t        DB_ctr[LLC_SETS][LLC_WAYS];

// Per-line RRPV
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Simple PC hashing
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

// Initialize replacement state
void InitReplacementState() {
    // 1) Initialize RRPVs and dead-block counters
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w]   = MAX_RRPV;
            DB_ctr[s][w] = 0;
        }
    }
    // 2) Initialize SHiP signature table
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_INIT;
    }
    // 3) Initialize DIP PSEL and leader sets
    PSEL = PSEL_INIT;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        uint32_t slot = s & (DUELERS - 1);
        isBIPLeader[s] = (slot < LEADER_QUOTA);
        isLRULeader[s] = (slot >= LEADER_QUOTA && slot < 2 * LEADER_QUOTA);
    }
}

// Victim selection: prefer dead blocks (DB_ctr==0) at MAX_RRPV
uint32_t GetVictimInSet(
    uint32_t cpu, uint32_t set,
    const BLOCK *current_set,
    uint64_t PC, uint64_t paddr,
    uint32_t type
) {
    while (true) {
        // first scan for MAX_RRPV && dead
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV && DB_ctr[set][w] == 0) {
                return w;
            }
        }
        // then any MAX_RRPV
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // age all
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] < MAX_RRPV) {
                RRPV[set][w]++;
            }
        }
    }
}

// Update on hit or miss
void UpdateReplacementState(
    uint32_t cpu, uint32_t set, uint32_t way,
    uint64_t paddr, uint64_t PC, uint64_t victim_addr,
    uint32_t type, uint8_t hit
) {
    uint32_t sig = PCIndex(PC, SIG_MASK);

    if (hit) {
        // Hit: promote, train SHiP, reset dead-block
        RRPV[set][way]   = 0;
        if (SigTable[sig] < SIG_MAX) {
            SigTable[sig]++;
        }
        DB_ctr[set][way] = DB_MAX;
        return;
    }

    // Miss: update DIP PSEL in leader sets
    if (isBIPLeader[set]) {
        // BIP performed here and missed => worse performance for BIP
        if (PSEL > 0) PSEL--;
    } else if (isLRULeader[set]) {
        // LRU missed => LRU worse => favor BIP
        if (PSEL < PSEL_MAX) PSEL++;
    }

    // Determine DIP choice for followers
    bool use_bip;
    if (isBIPLeader[set]) {
        use_bip = true;
    } else if (isLRULeader[set]) {
        use_bip = false;
    } else {
        // PSEL > midpoint => choose BIP else LRU
        use_bip = (PSEL > (PSEL_MAX / 2));
    }

    // Final insertion decision: SHiP hot overrides DIP
    bool is_hot = (SigTable[sig] >= (SIG_MAX / 2 + 1));
    if (is_hot) {
        RRPV[set][way] = 0;
    } else if (!use_bip) {
        // LRU insertion
        RRPV[set][way] = 0;
    } else {
        // BIP insertion: cold with 31/32, hot with 1/32
        uint32_t lowbits = PCIndex(PC, 31);
        if (lowbits == 0) {
            RRPV[set][way] = 0;
        } else {
            RRPV[set][way] = MAX_RRPV;
        }
    }
    // Newly inserted block starts as “alive”
    DB_ctr[set][way] = DB_MAX;
}

// Statistics (unused)
void PrintStats() { }
void PrintStats_Heartbeat() { }