#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters
static const uint8_t  MAX_RRPV        = 3;  // 2-bit RRPV [0..3]
static const uint8_t  SRRIP_INSERT    = (MAX_RRPV - 1);

// DRRIP set-dueling
static const uint32_t DUELERS         = 64;
static const uint32_t LEADER_QUOTA    = 32;
static const uint16_t PSEL_MAX        = 1023; // 10-bit
static const uint16_t PSEL_INIT       = PSEL_MAX/2;
static uint16_t       PSEL;
static uint8_t        isSRRIpleader[LLC_SETS];
static uint8_t        isBRRIpleader[LLC_SETS];

// SHiP-lite PC signature
static const uint32_t SIG_BITS        = 10;
static const uint32_t SIG_TABLE_SZ    = (1 << SIG_BITS);
static const uint8_t  SIG_MAX         = 3;    // 2-bit counter [0..3]
static uint8_t        SigTable[SIG_TABLE_SZ];

// Dead-block counters
static const uint8_t  DB_MAX          = 3;    // 2-bit [0..3]
static uint8_t        DB_ctr[LLC_SETS][LLC_WAYS];

// RRIP RRPVs
static uint8_t        RRPV[LLC_SETS][LLC_WAYS];

// Streaming detector per set
static uint64_t       LastAddr[LLC_SETS];
static uint64_t       LastDelta[LLC_SETS];
static uint8_t        StreamConf[LLC_SETS];

// Simple PC hash
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    // Init RRPV, dead-blocks
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w]   = MAX_RRPV;
            DB_ctr[s][w] = 0;
        }
        // Streaming detector
        LastAddr[s]  = 0;
        LastDelta[s] = 0;
        StreamConf[s]= 0;
    }
    // Init SHiP signatures to weakly unused
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_MAX/2;
    }
    // Init DRRIP PSEL and leader sets
    PSEL = PSEL_INIT;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        uint32_t slot = s & (DUELERS - 1);
        isSRRIpleader[s] = (slot < LEADER_QUOTA);
        isBRRIpleader[s] = (slot >= LEADER_QUOTA && slot < 2*LEADER_QUOTA);
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
    // 1) Dead-block at max RRPV
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV && DB_ctr[set][w] == 0) {
            return w;
        }
    }
    // 2) Any at max RRPV
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV) {
            return w;
        }
    }
    // 3) Age others
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
        // Promote on hit
        RRPV[set][way]   = 0;
        if (SigTable[sig] < SIG_MAX) SigTable[sig]++;
        DB_ctr[set][way] = DB_MAX;
        return;
    }

    // MISS --------------------------------------------------------
    // 1) DRRIP leader feedback
    if (isSRRIpleader[set]) {
        // SRRIP leader miss => SRRIP too weak => favor BRRIP
        if (PSEL > 0) PSEL--;
    } else if (isBRRIpleader[set]) {
        // BRRIP leader miss => BRRIP too weak => favor SRRIP
        if (PSEL < PSEL_MAX) PSEL++;
    }

    // 2) Streaming detection
    uint64_t delta = (LastAddr[set] ? paddr - LastAddr[set] : 0);
    if (delta && delta == LastDelta[set]) {
        StreamConf[set]++;
    } else {
        StreamConf[set] = 0;
    }
    LastDelta[set] = delta;
    LastAddr[set]  = paddr;

    bool isStream = (StreamConf[set] >= 1);

    // 3) Decide insertion RRPV
    if (isStream) {
        // Bypass streaming: deep insert + no dead-block budget
        RRPV[set][way]   = MAX_RRPV;
        DB_ctr[set][way] = 0;
    } else if (SigTable[sig] > (SIG_MAX/2)) {
        // Hot PC: MRU
        RRPV[set][way]   = 0;
        DB_ctr[set][way] = DB_MAX;
    } else {
        // DRRIP decision
        bool useSRRIP = (PSEL >= (PSEL_MAX/2));
        RRPV[set][way]   = useSRRIP ? SRRIP_INSERT : MAX_RRPV;
        DB_ctr[set][way] = DB_MAX;
    }
}

void PrintStats() {
    // No additional stats
}

void PrintStats_Heartbeat() {
    // No-op
}