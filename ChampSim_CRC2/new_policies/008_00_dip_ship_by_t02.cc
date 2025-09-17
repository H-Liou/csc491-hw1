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

// DIP dueling parameters
static const uint32_t DUELERS        = 64;    // 32 BIP + 32 SHiP leader sets
static const uint32_t LEADER_QUOTA   = 32;    // each
static const uint16_t PSEL_MAX       = 1023;  // 10-bit
static const uint16_t PSEL_INIT      = PSEL_MAX / 2;
static uint16_t       PSEL;
static bool           isBIPLeader[LLC_SETS];
static bool           isSHIPLeader[LLC_SETS];

// SHiP-lite signature table
static const uint32_t SIG_BITS       = 12;
static const uint32_t SIG_TABLE_SZ   = (1 << SIG_BITS);
static const uint32_t SIG_MASK       = (SIG_TABLE_SZ - 1);
static const uint8_t  SIG_MAX        = 7;    // 3-bit max
static const uint8_t  SIG_INIT       = 4;    // start neutral
static const uint8_t  HOT_THRES      = 5;    // >=5 => hot
static uint8_t        SigTable[SIG_TABLE_SZ];

// Streaming detector
static const uint32_t STREAM_BITS     = 8;
static const uint32_t STREAM_TABLE_SZ = (1 << STREAM_BITS);
static const uint32_t STREAM_MASK     = (STREAM_TABLE_SZ - 1);
static const uint8_t  STREAM_MAX      = 3;    // 2-bit saturating
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

// BIP: cold insertion except ~1/32 of the time we insert hot.
static inline bool BIP_winner(uint64_t PC) {
    // use low bits of PC to approximate a 1/32 random
    return ((PC ^ (PC >> 5)) & 0x1F) == 0;
}

void InitReplacementState() {
    // 1) Init RRPVs
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // 2) Init SHiP signature table
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_INIT;
    }
    // 3) Init streaming detector
    for (uint32_t i = 0; i < STREAM_TABLE_SZ; i++) {
        StreamTable[i].last_block  = 0;
        StreamTable[i].last_stride = 0;
        StreamTable[i].count       = 0;
    }
    // 4) Init DIP PSEL and leader sets
    PSEL = PSEL_INIT;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        uint32_t slot = s & (DUELERS - 1);
        isBIPLeader[s]  = (slot < LEADER_QUOTA);
        isSHIPLeader[s] = (slot >= LEADER_QUOTA && slot < 2 * LEADER_QUOTA);
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
    // SRRIP-style victim search
    while (true) {
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
    // 1) signature for SHiP
    uint32_t sig = PCIndex(PC, SIG_MASK);

    // 2) update streaming detector
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

    // On a hit: always promote & train SHiP
    if (hit) {
        RRPV[set][way] = 0;
        if (SigTable[sig] < SIG_MAX) SigTable[sig]++;
        // adjust DIP PSEL
        if (isBIPLeader[set]) {
            if (PSEL > 0) PSEL--;
        } else if (isSHIPLeader[set]) {
            if (PSEL < PSEL_MAX) PSEL++;
        }
        return;
    }

    // On a miss & streaming => bypass
    if (is_stream) {
        RRPV[set][way] = MAX_RRPV;
        return;
    }

    // Choose policy: leader or follower
    bool use_ship;
    if (isBIPLeader[set]) {
        use_ship = false;
    } else if (isSHIPLeader[set]) {
        use_ship = true;
    } else {
        use_ship = (PSEL > (PSEL_MAX / 2));
    }

    // Insertion
    if (!use_ship) {
        // BIP insertion
        if (BIP_winner(PC)) {
            RRPV[set][way] = 0;             // rare hot
        } else {
            RRPV[set][way] = MAX_RRPV;      // cold
        }
    } else {
        // SHiP-lite insertion
        uint8_t ctr = SigTable[sig];
        if (ctr >= HOT_THRES) {
            RRPV[set][way] = 0;             // hot
        } else if (ctr == 0) {
            RRPV[set][way] = MAX_RRPV;      // cold
        } else {
            RRPV[set][way] = NEUTRAL_RRPV;  // neutral
        }
    }
}

void PrintStats() {
    // nothing extra
}

void PrintStats_Heartbeat() {
    // nothing extra
}