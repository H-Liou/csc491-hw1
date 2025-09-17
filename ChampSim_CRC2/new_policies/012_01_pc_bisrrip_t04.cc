#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters
static const uint8_t  MAX_RRPV        = 3;    // 2-bit RRPV [0..3]
static const uint8_t  SRRIP_INSERT    = (MAX_RRPV - 1);

// Bimodal insertion probability (1 in BIP_PROB)
static const uint32_t BIP_PROB        = 32;

// PC-signature table
static const uint32_t SIG_BITS        = 12;            // 4096 entries
static const uint32_t SIG_TABLE_SZ    = (1 << SIG_BITS);
static const uint8_t  SIG_MAX         = 7;             // saturates [0..7]
static const uint8_t  SIG_INIT        = SIG_MAX / 2;   // 3
static uint8_t        SigTable[SIG_TABLE_SZ];

// Per-PC streaming detector
static const uint32_t PCSTRIDE_BITS   = 10;            // 1024 entries
static const uint32_t PCSTRIDE_SZ     = (1 << PCSTRIDE_BITS);
static const uint8_t  PCSTRIDE_TH     = 2;             // threshold for stream
struct PCStreamEntry {
    uint32_t last_addr;    // block address lower 32b
    uint32_t last_delta;   // last delta in blocks
    uint8_t  count;        // repeat count
};
static PCStreamEntry PCStream[PCSTRIDE_SZ];

// RRPV per block
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Simple PC hash
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    // Mix bits and mask
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

// Decide BIP promotion (1/BIP_PROB chance) based on PC low bits
static inline bool BIPDecision(uint64_t PC) {
    return ((PC >> 2) & (BIP_PROB - 1)) == 0;
}

void InitReplacementState() {
    // Initialize RRPVs to far
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Initialize PC signatures
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_INIT;
    }
    // Initialize per-PC stride entries
    for (uint32_t i = 0; i < PCSTRIDE_SZ; i++) {
        PCStream[i].last_addr  = 0;
        PCStream[i].last_delta = 0;
        PCStream[i].count      = 0;
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
    // RRIP victim search: look for RRPV==MAX, else age and retry
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // age
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] < MAX_RRPV) {
                RRPV[set][w]++;
            }
        }
    }
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
    uint32_t sig_idx    = PCIndex(PC, SIG_TABLE_SZ - 1);
    uint32_t str_idx    = PCIndex(PC, PCSTRIDE_SZ - 1);
    uint32_t blk_addr   = uint32_t(paddr >> 6); // block‐aligned
    uint8_t  *sig       = &SigTable[sig_idx];
    PCStreamEntry *pe   = &PCStream[str_idx];

    if (hit) {
        // On hit: promote and strengthen signature
        RRPV[set][way] = 0;
        if (*sig < SIG_MAX) (*sig)++;
        return;
    }

    // MISS --------------------------------------------------------
    // 1) Streaming detection per-PC
    uint32_t delta = blk_addr - pe->last_addr;
    if (delta != 0 && delta == pe->last_delta) {
        if (pe->count < 0xFF) pe->count++;
    } else {
        pe->count = 0;
    }
    pe->last_delta = delta;
    pe->last_addr  = blk_addr;
    bool is_stream = (pe->count >= PCSTRIDE_TH);

    // 2) SHiP-lite signature decrement on miss
    if (*sig > 0) (*sig)--;

    // 3) Decide insertion RRPV
    if (is_stream) {
        // pure stream => bypass
        RRPV[set][way] = MAX_RRPV;
    }
    else if (*sig >= 6) {
        // very hot PC => MRU
        RRPV[set][way] = 0;
    }
    else if (*sig >= 3) {
        // medium reuse => SRRIP depth
        RRPV[set][way] = SRRIP_INSERT;
    }
    else {
        // cold PC => BIP with rare SRRIP insert
        if (BIPDecision(PC)) {
            RRPV[set][way] = SRRIP_INSERT;
        } else {
            RRPV[set][way] = MAX_RRPV;
        }
    }
}

void PrintStats() {
    // No extra stats
}

void PrintStats_Heartbeat() {
    // No-op
}