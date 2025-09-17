#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRPV parameters
static const uint8_t MAX_RRPV       = 3;
static const uint8_t NEUTRAL_RRPV   = (MAX_RRPV - 1);

// SHiP-lite signature table
static const uint32_t SIG_BITS      = 12;
static const uint32_t SIG_TABLE_SZ  = (1 << SIG_BITS);
static const uint32_t SIG_MASK      = (SIG_TABLE_SZ - 1);
static const uint8_t  SIG_MAX       = 7;    // 3-bit max
static const uint8_t  SIG_INIT      = 4;    // start neutral
static const uint8_t  HOT_THRES     = 5;    // >=5 => hot
static uint8_t        SigTable[SIG_TABLE_SZ];

// Per-block RRPVs
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Streaming detector
static const uint32_t STREAM_BITS       = 8;
static const uint32_t STREAM_TABLE_SZ   = (1 << STREAM_BITS);
static const uint32_t STREAM_MASK       = (STREAM_TABLE_SZ - 1);
static const uint8_t  STREAM_MAX        = 3;   // 2-bit saturating
struct StreamEntry {
    uint32_t last_block;
    int32_t last_stride;
    uint8_t count;
};
static StreamEntry StreamTable[STREAM_TABLE_SZ];

// Simple PC hashing
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    // Initialize all RRPVs to long (MAX_RRPV)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Initialize SHiP signature counters
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_INIT;
    }
    // Initialize streaming entries
    for (uint32_t i = 0; i < STREAM_TABLE_SZ; i++) {
        StreamTable[i].last_block  = 0;
        StreamTable[i].last_stride = 0;
        StreamTable[i].count       = 0;
    }
}

// SRRIP-style victim selection
uint32_t GetVictimInSet(
    uint32_t cpu, uint32_t set,
    const BLOCK *current_set,
    uint64_t PC, uint64_t paddr,
    uint32_t type
) {
    // Find any line with RRPV == MAX_RRPV
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Age everyone by one
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
    // 1) SHiP signature index
    uint32_t sig = PCIndex(PC, SIG_MASK);

    // 2) Streaming detection update
    uint32_t blk_addr = uint32_t(paddr >> 6);
    uint32_t sid      = PCIndex(PC, STREAM_MASK);
    StreamEntry &e    = StreamTable[sid];
    int32_t stride    = int32_t(blk_addr - e.last_block);

    if (stride == e.last_stride) {
        if (e.count < STREAM_MAX) e.count++;
    } else {
        if (e.count > 0) e.count--;
        e.last_stride = stride;
    }
    e.last_block = blk_addr;
    bool is_stream = (e.count >= STREAM_MAX);

    // On a hit => strongly promote and train SHiP
    if (hit) {
        RRPV[set][way] = 0;
        if (SigTable[sig] < SIG_MAX) {
            SigTable[sig]++;
        }
        return;
    }

    // MISS: if this PC is streaming, effectively bypass by keeping RRPV=MAX
    if (is_stream) {
        return;
    }

    // MISS & not streaming: use SHiP-lite to choose insertion depth
    uint8_t counter = SigTable[sig];
    uint8_t new_rrpv;
    if (counter >= HOT_THRES) {
        // hot => front priority
        new_rrpv = 0;
    } else if (counter == 0) {
        // cold => long RRPV
        new_rrpv = MAX_RRPV;
    } else {
        // neutral => medium (SRRIP)
        new_rrpv = NEUTRAL_RRPV;
    }
    RRPV[set][way] = new_rrpv;
}

void PrintStats() {
    // no extra stats
}

void PrintStats_Heartbeat() {
    // no heartbeat stats
}