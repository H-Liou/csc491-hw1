#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRIP parameters
static const uint8_t  MAX_RRPV        = 3;
static const uint8_t  NEUTRAL_RRPV    = (MAX_RRPV - 1);

// DRRIP dueling parameters
static const uint32_t DRRIP_DUELERS   = 64;    // 32 SRRIP + 32 BIP
static const uint32_t DRRIP_LEADERS   = 32;
static const uint16_t PSEL_MAX        = 1023;  // 10-bit
static const uint16_t PSEL_INIT       = (PSEL_MAX / 2);
static uint16_t       PSEL;

// BIP parameter: 1/64 chance of MRU insertion
static const uint32_t BIP_PROB        = 64;

// SHiP signature table (2-bit counters)
static const uint32_t SIG_BITS        = 10;
static const uint32_t SIG_TABLE_SZ    = (1 << SIG_BITS);
static const uint32_t SIG_MASK        = (SIG_TABLE_SZ - 1);
static const uint8_t  SIG_MAX         = 3;
static const uint8_t  SIG_INIT        = 1;
static uint8_t        SigTable[SIG_TABLE_SZ];

// Per-PC streaming detector (2-bit counters)
static uint8_t        StreamTable[SIG_TABLE_SZ];
// Track last miss address & stride
static uint64_t       last_miss_addr;
static int64_t        last_miss_delta;

// Per-line RRPV
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Helpers
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}
static inline bool isSRRIPLeader(uint32_t set) {
    return ((set & (DRRIP_DUELERS - 1)) < DRRIP_LEADERS);
}
static inline bool isBIPLeader(uint32_t set) {
    uint32_t slot = (set & (DRRIP_DUELERS - 1));
    return (slot >= DRRIP_LEADERS && slot < 2 * DRRIP_LEADERS);
}

// Initialize replacement state
void InitReplacementState() {
    // Reset per-line RRPVs
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Initialize SHiP and stream tables
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i]    = SIG_INIT;
        StreamTable[i] = 0;
    }
    // Initialize DRRIP PSEL and stream tracker
    PSEL            = PSEL_INIT;
    last_miss_addr  = 0;
    last_miss_delta = 0;
}

// Victim selection: find RRPV == MAX; if none, age all and retry
uint32_t GetVictimInSet(
    uint32_t cpu, uint32_t set,
    const BLOCK *current_set,
    uint64_t PC, uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // age everyone
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
        // On hit: make MRU and train SHiP
        RRPV[set][way] = 0;
        if (SigTable[sig] < SIG_MAX) {
            SigTable[sig]++;
        }
        return;
    }

    // STREAM DETECTION: update per-PC stream counter
    int64_t delta = int64_t(paddr) - int64_t(last_miss_addr);
    if (last_miss_addr != 0 && delta == last_miss_delta) {
        if (StreamTable[sig] < SIG_MAX) StreamTable[sig]++;
    } else {
        if (StreamTable[sig] > 0) StreamTable[sig]--;
    }
    last_miss_addr  = paddr;
    last_miss_delta = delta;

    // DRRIP PSEL update in leader sets
    if (isSRRIPLeader(set)) {
        // SRRIP had a miss => favor BIP
        if (PSEL < PSEL_MAX) PSEL++;
    } else if (isBIPLeader(set)) {
        // BIP had a miss => favor SRRIP
        if (PSEL > 0) PSEL--;
    }

    // Decide insertion RRPV
    // 1) Bypass true streams
    if (StreamTable[sig] >= 2) {
        RRPV[set][way] = MAX_RRPV;
        return;
    }
    // 2) SHiP‐hot blocks
    if (SigTable[sig] >= 2) {
        RRPV[set][way] = 0;
        return;
    }
    // 3) DRRIP choice: SRRIP vs BIP
    bool use_bip;
    if (isSRRIPLeader(set)) {
        use_bip = false;
    } else if (isBIPLeader(set)) {
        use_bip = true;
    } else {
        use_bip = (PSEL > (PSEL_MAX / 2));
    }
    if (!use_bip) {
        // SRRIP insertion: warm but not MRU
        RRPV[set][way] = NEUTRAL_RRPV;
    } else {
        // BIP insertion: cold except 1/64 chance MRU
        uint32_t roll = PCIndex(PC, BIP_PROB - 1);
        RRPV[set][way] = (roll == 0 ? 0 : MAX_RRPV);
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // (No additional statistics)
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // (No additional statistics)
}