#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRPV parameters
static const uint8_t MAX_RRPV       = 3;
static const uint8_t SRRIP_RRPV     = (MAX_RRPV - 1);

// DIP-style set dueling parameters
static const uint16_t PSEL_BITS     = 10;
static const uint16_t PSEL_MAX      = ((1 << PSEL_BITS) - 1);
static const uint16_t PSEL_INIT     = (PSEL_MAX >> 1);
static uint16_t       PSEL;

// SHiP-lite signature table
static const uint32_t SIG_BITS      = 12;
static const uint32_t SIG_TABLE_SZ  = (1 << SIG_BITS);
static const uint32_t SIG_MASK      = (SIG_TABLE_SZ - 1);
static const uint8_t  SIG_MAX       = 7;    // 3-bit counter max
static const uint8_t  SIG_INIT      = 4;    // start neutral
static const uint8_t  HOT_THRES     = 5;    // >=5 deemed hot
static uint8_t        SigTable[SIG_TABLE_SZ];

// Streaming detector table (per-PC entries)
static const uint32_t STREAM_BITS   = 9;
static const uint32_t STREAM_SZ     = (1 << STREAM_BITS);
static const uint32_t STREAM_MASK   = (STREAM_SZ - 1);
struct StreamEntry {
    uint64_t last_addr;
    int64_t  last_delta;
    uint8_t  streak;
} StreamTable[STREAM_SZ];

// Per-block RRPVs
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Bimodal counter for occasional SRRIP insertion
static uint32_t brip_ctr = 0;

// Simple hash of PC to index tables
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    // Initialize RRPVs to long (MAX_RRPV)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Initialize signature counters to neutral
    for (uint32_t i = 0; i < SIG_TABLE_SZ; i++) {
        SigTable[i] = SIG_INIT;
    }
    // Initialize streaming detector
    for (uint32_t i = 0; i < STREAM_SZ; i++) {
        StreamTable[i].last_addr  = 0;
        StreamTable[i].last_delta = 0;
        StreamTable[i].streak     = 0;
    }
    // Initialize DIP PSEL
    PSEL = PSEL_INIT;
}

// SRRIP victim selection (evict any line with RRPV==MAX_RRPV)
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
        // Age everyone by one if no candidate
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
    // Compute PC signature and streaming index
    uint32_t sig = PCIndex(PC, SIG_MASK);
    uint32_t sid = PCIndex(PC, STREAM_MASK);

    // Streaming detection: look for steady ±1-line deltas
    bool is_stream = false;
    {
        uint64_t curr = paddr;
        int64_t delta = int64_t(curr) - int64_t(StreamTable[sid].last_addr);
        if (delta == StreamTable[sid].last_delta && (delta == 64 || delta == -64)) {
            StreamTable[sid].streak++;
            if (StreamTable[sid].streak >= 2) {
                is_stream = true;
            }
        } else {
            StreamTable[sid].streak     = 1;
            StreamTable[sid].last_delta = delta;
        }
        StreamTable[sid].last_addr = curr;
    }

    // Identify leader sets for DIP
    bool is_lip_leader = ((set & 63) == 0);
    bool is_bip_leader = ((set & 63) == 1);

    if (hit) {
        // On hit: strong promotion and train SHiP
        RRPV[set][way] = 0;
        if (SigTable[sig] < SIG_MAX) {
            SigTable[sig]++;
        }
        // Train DIP PSEL in leader sets (only for non-hot/non-stream lines)
        if (!(SigTable[sig] >= HOT_THRES || is_stream)) {
            if (is_lip_leader && PSEL < PSEL_MAX) {
                PSEL++;
            } else if (is_bip_leader && PSEL > 0) {
                PSEL--;
            }
        }
        return;
    }

    // On miss: choose insertion RRPV
    uint8_t new_rrpv;
    // 1) Hot from SHiP → RRPV=0
    if (SigTable[sig] >= HOT_THRES) {
        new_rrpv = 0;
    }
    // 2) Streaming → treat as cold
    else if (is_stream) {
        new_rrpv = MAX_RRPV;
    }
    // 3) DIP leader sets: fixed policy
    else if (is_lip_leader) {
        new_rrpv = 0;
    }
    else if (is_bip_leader) {
        if ((brip_ctr++ & 31) == 0) new_rrpv = SRRIP_RRPV;
        else                        new_rrpv = MAX_RRPV;
    }
    // 4) DIP follower sets: choose by PSEL
    else {
        if (PSEL > (PSEL_MAX >> 1)) {
            new_rrpv = 0;
        } else {
            if ((brip_ctr++ & 31) == 0) new_rrpv = SRRIP_RRPV;
            else                        new_rrpv = MAX_RRPV;
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