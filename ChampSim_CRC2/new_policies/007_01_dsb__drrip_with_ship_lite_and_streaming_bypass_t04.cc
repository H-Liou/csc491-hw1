#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters
static const uint8_t RRPV_BITS     = 2;
static const uint8_t MAX_RRPV       = (1 << RRPV_BITS) - 1; // 3
static const uint8_t SRRIP_INSERT   = MAX_RRPV - 1;         // 2
static const uint8_t BRRIP_PROB     = 32;                   // 1/32 chance for BRRIP to insert at SRRIP_INSERT

// DRRIP dueling
static const uint32_t LEADER_DISTANCE = 32;
static const uint16_t PSEL_MAX        = 1023;
static const uint16_t PSEL_INIT       = PSEL_MAX / 2;
static uint16_t PSEL;  // saturating selector, >=512 ⇒ choose BRRIP

// SHiP-lite signature table
static const uint32_t SIG_BITS      = 12;
static const uint32_t SIG_TABLE_SZ  = (1 << SIG_BITS);
static const uint32_t SIG_MASK      = (SIG_TABLE_SZ - 1);
static const uint8_t  SIG_INIT      = 4;
static const uint8_t  SIG_MAX       = 7;   // 3-bit max
static const uint8_t  HOT_THRES     = 5;
static uint8_t SigTable[SIG_TABLE_SZ];

// Streaming detector
static const uint32_t STREAM_BITS       = 8;
static const uint32_t STREAM_TABLE_SZ   = (1 << STREAM_BITS);
static const uint32_t STREAM_MASK       = (STREAM_TABLE_SZ - 1);
static const uint8_t  STREAM_MAX        = 3;
struct StreamEntry {
    uint32_t last_block;
    int32_t  last_stride;
    uint8_t  count;
};
static StreamEntry StreamTable[STREAM_TABLE_SZ];

// Per-block RRPVs
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Simple PC hashing
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

// Determine if this set is an SRRIP or BRRIP leader
static inline bool IsSRLeader(uint32_t set) {
    return (set % LEADER_DISTANCE) == 0;
}
static inline bool IsBRLeader(uint32_t set) {
    return (set % LEADER_DISTANCE) == (LEADER_DISTANCE/2);
}

// Initialization
void InitReplacementState() {
    // RRPVs
    for (uint32_t s = 0; s < LLC_SETS; s++)
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            RRPV[s][w] = MAX_RRPV;

    // PSEL
    PSEL = PSEL_INIT;

    // SHiP signatures
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++)
        SigTable[i] = SIG_INIT;

    // Streaming detector
    for (uint32_t i = 0; i < STREAM_TABLE_SZ; i++) {
        StreamTable[i].last_block  = 0;
        StreamTable[i].last_stride = 0;
        StreamTable[i].count       = 0;
    }
}

// Victim: classical SRRIP scan
uint32_t GetVictimInSet(
    uint32_t cpu, uint32_t set,
    const BLOCK *current_set,
    uint64_t PC, uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (RRPV[set][w] == MAX_RRPV)
                return w;
        // age all
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (RRPV[set][w] < MAX_RRPV)
                RRPV[set][w]++;
    }
}

// Update on hit/miss
void UpdateReplacementState(
    uint32_t cpu, uint32_t set, uint32_t way,
    uint64_t paddr, uint64_t PC, uint64_t victim_addr,
    uint32_t type, uint8_t hit
) {
    // 1) Compute PC signature
    uint32_t sig       = PCIndex(PC, SIG_MASK);

    // 2) Streaming detection
    uint32_t blk_addr  = uint32_t(paddr >> 6);
    uint32_t sid       = PCIndex(PC, STREAM_MASK);
    auto &e            = StreamTable[sid];
    int32_t stride     = int32_t(blk_addr - e.last_block);
    if (stride == e.last_stride) {
        if (e.count < STREAM_MAX) e.count++;
    } else {
        if (e.count > 0) e.count--;
        e.last_stride = stride;
    }
    e.last_block = blk_addr;
    bool is_stream = (e.count >= STREAM_MAX);

    if (hit) {
        // Always promote on hit
        RRPV[set][way] = 0;
        if (SigTable[sig] < SIG_MAX) SigTable[sig]++;
        return;
    }

    // MISS ⇒ DRRIP dueling (leader sets update PSEL)
    if (IsSRLeader(set)) {
        if (PSEL > 0) PSEL--;
    } else if (IsBRLeader(set)) {
        if (PSEL < PSEL_MAX) PSEL++;
    }

    // Decide insertion depth
    uint8_t new_rrpv;
    if (SigTable[sig] >= HOT_THRES) {
        // Strong hot ⇒ front
        new_rrpv = 0;
    } else if (is_stream) {
        // Streaming bypass
        new_rrpv = MAX_RRPV;
    } else {
        // Follow current RRIP policy
        bool use_brrip = (PSEL >= (PSEL_MAX/2));
        if (!use_brrip) {
            // SRRIP
            new_rrpv = SRRIP_INSERT;
        } else {
            // BRRIP: mostly insert at long, occasionally at SRRIP_INSERT
            uint32_t rnd = PCIndex(PC, BRRIP_PROB-1);
            new_rrpv = (rnd == 0 ? SRRIP_INSERT : MAX_RRPV);
        }
    }
    RRPV[set][way] = new_rrpv;
}

void PrintStats() {
    // no extra stats
}

void PrintStats_Heartbeat() {
    // no heartbeat stats
}