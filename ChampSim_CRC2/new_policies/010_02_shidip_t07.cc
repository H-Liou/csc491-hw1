#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters
static const uint8_t  MAX_RRPV     = 3;

// DIP-style set dueling
static const uint32_t DUELER_SETS  = 64;        // total leader sets
static const uint32_t LEADER_QUOTA = 32;        // per each policy
static const uint16_t PSEL_MAX     = 1023;      // 10-bit
static uint16_t       PSEL;                    // dynamic selector
static uint8_t        isLIPLeader[LLC_SETS];
static uint8_t        isBIPLeader[LLC_SETS];

// SHiP signature table
static const uint32_t SIG_BITS     = 10;
static const uint32_t SIG_SZ       = (1 << SIG_BITS);
static const uint32_t SIG_MASK     = SIG_SZ - 1;
static const uint8_t  SIG_MAX      = 3;
static uint8_t        SigTable[SIG_SZ];        // 2-bit counters

// Streaming detector per‐PC
static const uint32_t ST_BITS      = 10;
static const uint32_t ST_SZ        = (1 << ST_BITS);
static const uint32_t ST_MASK      = ST_SZ - 1;
static uint64_t       StreamLast[ST_SZ];
static uint8_t        StreamCount[ST_SZ];
static const uint8_t  STREAM_TH    = 2;

// Per-line RRPV
static uint8_t        RRPV[LLC_SETS][LLC_WAYS];

// Simple PC hash
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    // XOR-fold + mask
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    // Initialize RRPV
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Init SHiP signatures
    for (uint32_t i = 0; i < SIG_SZ; i++) {
        SigTable[i] = SIG_MAX / 2;
    }
    // Init DIP PSEL and leaders
    PSEL = PSEL_MAX / 2;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        uint32_t slot = s & (DUELER_SETS - 1);
        isLIPLeader[s] = (slot < LEADER_QUOTA);
        isBIPLeader[s] = (slot >= LEADER_QUOTA && slot < 2 * LEADER_QUOTA);
    }
    // Init streaming detector
    for (uint32_t i = 0; i < ST_SZ; i++) {
        StreamLast[i]  = 0;
        StreamCount[i] = 0;
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu, uint32_t set,
    const BLOCK *current_set,
    uint64_t PC, uint64_t paddr,
    uint32_t type
) {
    // Prefer highest RRPV
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Age all lines
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] < MAX_RRPV) {
                RRPV[set][w]++;
            }
        }
    }
}

void UpdateReplacementState(
    uint32_t cpu, uint32_t set, uint32_t way,
    uint64_t paddr, uint64_t PC, uint64_t victim_addr,
    uint32_t type, uint8_t hit
) {
    uint32_t sig = PCIndex(PC, SIG_MASK);
    uint32_t sidx= PCIndex(PC, ST_MASK);

    // Streaming detection
    uint64_t last_line = StreamLast[sidx] >> 6;
    uint64_t cur_line  = paddr >> 6;
    int64_t  delta     = int64_t(cur_line) - int64_t(last_line);
    if (delta == 1 || delta == -1) {
        if (StreamCount[sidx] < STREAM_TH) StreamCount[sidx]++;
    } else {
        StreamCount[sidx] = 0;
    }
    StreamLast[sidx] = paddr;

    if (hit) {
        // On hit: promote & train signature
        RRPV[set][way] = 0;
        if (SigTable[sig] < SIG_MAX) SigTable[sig]++;
        return;
    }

    // MISS: first update DIP leaders
    if (isLIPLeader[set]) {
        // LIP leader misses => LIP is poorer => favor BIP
        if (PSEL > 0) PSEL--;
    } else if (isBIPLeader[set]) {
        // BIP leader misses => BIP is poorer => favor LIP
        if (PSEL < PSEL_MAX) PSEL++;
    }

    // Streaming bypass?
    if (StreamCount[sidx] >= STREAM_TH) {
        // Bypass: insert at LRU
        RRPV[set][way] = MAX_RRPV;
        return;
    }

    // Decide insertion
    bool use_LIP;
    // Hot PC overrides
    if (SigTable[sig] == SIG_MAX) {
        use_LIP = true;
    } else {
        // follower uses PSEL
        use_LIP = (PSEL > (PSEL_MAX/2));
    }

    if (use_LIP) {
        // LIP insertion: MRU
        RRPV[set][way] = 0;
    } else {
        // BIP insertion: mostly LRU with small MRU chance
        // ~1/32 chance to insert MRU
        if ((PCIndex(PC,31) == 0)) {
            RRPV[set][way] = 0;
        } else {
            RRPV[set][way] = MAX_RRPV;
        }
    }
    // Train signature on miss downwards
    if (SigTable[sig] > 0) SigTable[sig]--;
}

void PrintStats() {
    // Optionally report PSEL
    std::cout << "PSEL=" << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats
}