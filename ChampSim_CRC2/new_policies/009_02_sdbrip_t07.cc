#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters
static const uint8_t  MAX_RRPV       = 3;
static const uint8_t  INSERT_RRPV    = 2;    // SRRIP insertion depth

// DRRIP dueling
static const uint32_t DUELERS        = 64;   // 32 SRRIP + 32 BRRIP
static const uint32_t LEADER_QUOTA   = 32;
static const uint16_t PSEL_MAX       = 1023; // 10-bit
static const uint16_t PSEL_INIT      = PSEL_MAX/2;
static uint16_t       PSEL;
static uint8_t        isSRRIPLeader[LLC_SETS];
static uint8_t        isBRRIPLeader[LLC_SETS];

// SHiP-lite signature table
static const uint32_t SIG_BITS       = 10;
static const uint32_t SIG_TABLE_SZ   = (1 << SIG_BITS);
static const uint32_t SIG_MASK       = SIG_TABLE_SZ - 1;
static const uint8_t  SIG_MAX        = 3;
static uint8_t        SigTable[SIG_TABLE_SZ];

// Dead-block approximation (2-bit per line)
static const uint8_t  DB_MAX         = 3;
static uint8_t        DB_ctr[LLC_SETS][LLC_WAYS];

// Per-line RRPV
static uint8_t        RRPV[LLC_SETS][LLC_WAYS];

// Streaming detector per‐PC (unit-stride runs)
static const uint32_t ST_BITS        = 10;
static const uint32_t ST_SZ          = (1 << ST_BITS);
static const uint32_t ST_MASK        = ST_SZ - 1;
static uint64_t       StreamLastAddr[ST_SZ];
static uint8_t        StreamCount[ST_SZ];

// Simple PC hash
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    // Initialize RRPV and dead‐block counters
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w]   = MAX_RRPV;
            DB_ctr[s][w] = 0;
        }
    }
    // Init SHiP signatures
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_MAX/2;
    }
    // Init DRRIP PSEL and leader sets
    PSEL = PSEL_INIT;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        uint32_t slot = s & (DUELERS-1);
        isSRRIPLeader[s] = (slot < LEADER_QUOTA);
        isBRRIPLeader[s] = (slot >= LEADER_QUOTA && slot < 2*LEADER_QUOTA);
    }
    // Init streaming detector
    for (uint32_t i = 0; i < ST_SZ; i++) {
        StreamLastAddr[i] = 0;
        StreamCount[i]    = 0;
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu, uint32_t set,
    const BLOCK *current_set,
    uint64_t PC, uint64_t paddr,
    uint32_t type
) {
    // First prefer dead blocks at RRPV==MAX
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV && DB_ctr[set][w] == 0) {
            return w;
        }
    }
    // Then any RRPV==MAX
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV) {
            return w;
        }
    }
    // Age and retry
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] < MAX_RRPV) {
            RRPV[set][w]++;
        }
    }
    // Recurse until we find one
    return GetVictimInSet(cpu, set, current_set, PC, paddr, type);
}

void UpdateReplacementState(
    uint32_t cpu, uint32_t set, uint32_t way,
    uint64_t paddr, uint64_t PC, uint64_t victim_addr,
    uint32_t type, uint8_t hit
) {
    uint32_t sig = PCIndex(PC, SIG_MASK);

    if (hit) {
        // Hit: promote
        RRPV[set][way]   = 0;
        // Train SHiP signature
        if (SigTable[sig] < SIG_MAX) SigTable[sig]++;
        // Reset dead‐block counter
        DB_ctr[set][way] = DB_MAX;
        return;
    }

    // MISS --------------------------------------------------------
    // 1) Update streaming detector for this PC
    uint32_t sidx = PCIndex(PC, ST_MASK);
    uint64_t last_line = StreamLastAddr[sidx] >> 6;
    uint64_t cur_line  = paddr >> 6;
    int64_t  delta     = int64_t(cur_line) - int64_t(last_line);
    if ( (delta == 1) || (delta == -1) ) {
        if (StreamCount[sidx] < 3) StreamCount[sidx]++;
    } else {
        StreamCount[sidx] = 0;
    }
    StreamLastAddr[sidx] = paddr;

    // 2) Leader miss updates
    if (isSRRIPLeader[set]) {
        // SRRIP miss => SRRIP poorer => favor BRRIP
        if (PSEL > 0) PSEL--;
    } else if (isBRRIPLeader[set]) {
        // BRRIP miss => BRRIP poorer => favor SRRIP
        if (PSEL < PSEL_MAX) PSEL++;
    }

    // 3) Streaming bypass?
    if (StreamCount[sidx] >= 2) {
        // Bypass: insert as dead, max RRPV
        RRPV[set][way]   = MAX_RRPV;
        DB_ctr[set][way] = 0;
        return;
    }

    // 4) DRRIP choice for followers
    bool use_srrip;
    if (isSRRIPLeader[set])        use_srrip = true;
    else if (isBRRIPLeader[set])   use_srrip = false;
    else                            use_srrip = (PSEL > (PSEL_MAX/2));

    // 5) Final insertion: SHiP-hot overrides RRIP mode
    if (SigTable[sig] >= (SIG_MAX/2 + 1)) {
        // Hot PC => immediate
        RRPV[set][way]   = 0;
    } else if (use_srrip) {
        // SRRIP: moderate life
        RRPV[set][way]   = INSERT_RRPV;
    } else {
        // BRRIP: mostly long life, occasionally moderate
        // 1/32 chance of moderate (RRPV=2)
        if (PCIndex(PC, 31) == 0) {
            RRPV[set][way] = INSERT_RRPV;
        } else {
            RRPV[set][way] = MAX_RRPV;
        }
    }
    // Newly inserted starts “alive”
    DB_ctr[set][way] = DB_MAX;
}

void PrintStats() {
    // Optionally print PSEL or streaming stats
}

void PrintStats_Heartbeat() {
    // No-op
}