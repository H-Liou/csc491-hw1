#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters
static const uint8_t  MAX_RRPV       = 3;     // 2-bit RRPV => [0..3]
static const uint8_t  SRRIP_RRPV     = MAX_RRPV - 1;  // near-MRU insertion
static const uint8_t  BRRIP_RRPV     = MAX_RRPV;      // deep insertion

// DRRIP dueling
static const uint32_t DUELERS        = 64;    // number of leader sets
static const uint32_t LEADER_QUOTA   = DUELERS/2;
static const uint16_t PSEL_MAX       = 1023;  // 10-bit counter
static const uint16_t PSEL_INIT      = PSEL_MAX/2;
static uint16_t       PSEL;
static uint8_t        isSRRIPLeader[LLC_SETS];
static uint8_t        isBRRIPLeader[LLC_SETS];

// SHiP-lite signature table
static const uint32_t SIG_BITS       = 10;
static const uint32_t SIG_TABLE_SZ   = (1 << SIG_BITS);
static const uint8_t  SIG_MAX        = 3;     // 2-bit counter => [0..3]
static uint8_t        SigTable[SIG_TABLE_SZ];

// Streaming detector table
// Tracks last block-ID, last delta, and a 2-bit confidence counter per PC signature
struct StrideEntry {
    uint16_t last_block;   // low bits of block address
    int8_t   last_delta;   // signed delta in cache lines
    uint8_t  conf;         // [0..3], >=2 => streaming
};
static StrideEntry StrTable[SIG_TABLE_SZ];

// Per-line metadata
static uint8_t        RRPV[LLC_SETS][LLC_WAYS];    // 2-bit RRPV per line
static uint8_t        DB_ctr[LLC_SETS][LLC_WAYS];  // 2-bit dead-block counter

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
    // Initialize SHiP signatures
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i]      = SIG_MAX/2;
        StrTable[i].last_block = 0;
        StrTable[i].last_delta = 0;
        StrTable[i].conf       = 0;
    }
    // Initialize PSEL and leader sets for DRRIP
    PSEL = PSEL_INIT;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        uint32_t slot = s & (DUELERS - 1);
        isSRRIPLeader[s] = (slot <  LEADER_QUOTA);
        isBRRIPLeader[s] = (slot >= LEADER_QUOTA && slot < 2*LEADER_QUOTA);
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK */* current_set */,
    uint64_t /* PC */,
    uint64_t /* paddr */,
    uint32_t /* type */
) {
    // 1) Evict any dead block at max RRPV
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV && DB_ctr[set][w] == 0)
            return w;
    }
    // 2) Evict any block at max RRPV
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV)
            return w;
    }
    // 3) Age everyone
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] < MAX_RRPV)
            RRPV[set][w]++;
    }
    // Retry
    return GetVictimInSet(cpu, set, nullptr, 0, 0, 0);
}

void UpdateReplacementState(
    uint32_t cpu,
    uint32_t set,
    uint32_t way,
    uint64_t paddr,
    uint64_t PC,
    uint64_t /* victim_addr */,
    uint32_t /* type */,
    uint8_t hit
) {
    uint32_t sig = PCIndex(PC, SIG_TABLE_SZ - 1);
    uint16_t blk_id = uint16_t((paddr >> 6) & 0xFFFF);
    int8_t   delta  = int8_t(blk_id - StrTable[sig].last_block);

    // Streaming detector update
    if (delta == StrTable[sig].last_delta) {
        if (StrTable[sig].conf < 3) StrTable[sig].conf++;
    } else {
        if (StrTable[sig].conf > 0) StrTable[sig].conf--;
        StrTable[sig].last_delta = delta;
    }
    StrTable[sig].last_block = blk_id;
    bool is_stream = (StrTable[sig].conf >= 2);

    if (hit) {
        // On hit: promote to MRU, train SHiP, refresh dead-block counter
        RRPV[set][way]   = 0;
        if (SigTable[sig] < SIG_MAX) SigTable[sig]++;
        DB_ctr[set][way] = DB_MAX;
        return;
    }

    // MISS --------------------------------------------------------
    // 1) DRRIP leader-set PSEL updates
    if (isSRRIPLeader[set]) {
        // SRRIP leader miss => SRRIP is poor => favor BRRIP
        if (PSEL > 0) PSEL--;
    } else if (isBRRIPLeader[set]) {
        // BRRIP leader miss => BRRIP is poor => favor SRRIP
        if (PSEL < PSEL_MAX) PSEL++;
    }

    // 2) Decide base insertion policy
    bool useSRRIP = (PSEL > (PSEL_MAX / 2));

    // 3) Streaming bypass: deep insert with no reuse credit, skip PSEL/SHiP influence
    if (is_stream) {
        RRPV[set][way]   = MAX_RRPV;
        DB_ctr[set][way] = 0;
        return;
    }

    // 4) SHiP override: hot PCs => MRU
    bool hotPC = (SigTable[sig] > (SIG_MAX/2));
    if (hotPC) {
        RRPV[set][way] = 0;
    } else {
        // Apply SRRIP vs BRRIP
        RRPV[set][way] = useSRRIP ? SRRIP_RRPV : BRRIP_RRPV;
    }
    DB_ctr[set][way] = DB_MAX;
}

void PrintStats() {
    // (Optional) print PSEL, streaming entries, etc.
}

void PrintStats_Heartbeat() {
    // no-op
}