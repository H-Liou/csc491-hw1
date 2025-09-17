#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP parameters
static const uint8_t MAX_RRPV = 3;
static const uint8_t INIT_RRPV = 2;

// SHiP-lite parameters
static const uint32_t SIG_SIZE = 1024;
static const uint32_t SIG_MASK = (SIG_SIZE - 1);

// Streaming detector
static const uint8_t STREAM_THRESH = 3;

// DRRIP set‐dueling
static const uint32_t DUEL_PERIOD = 64;      // mod distance
static const uint32_t LEADER_BIP_MAX = 32;   // [0..31]
static const uint32_t LEADER_SRRIP_MIN = 32; // [32..63]
static const uint32_t PSEL_MAX = 1023;
static const uint32_t PSEL_INIT = 512;
static const uint32_t PSEL_TH = 512;

// Replacement state
static uint8_t  RRPV[LLC_SETS][LLC_WAYS];
static uint8_t  SHCT[SIG_SIZE];              // 2-bit per-PC reuse counter
static uint32_t SD_last[SIG_SIZE];           // last block id per PC
static uint8_t  SD_count[SIG_SIZE];          // stride run length per PC
static uint32_t PSEL;                        // 10-bit policy selector

// Helper: hash PC to signature
static inline uint32_t Signature(uint64_t PC) {
    return uint32_t((PC ^ (PC >> 12)) & SIG_MASK);
}

// Identify leader sets
static inline bool is_leader_bip(uint32_t set) {
    uint32_t m = set & (DUEL_PERIOD - 1);
    return (m < LEADER_BIP_MAX);
}
static inline bool is_leader_srrip(uint32_t set) {
    uint32_t m = set & (DUEL_PERIOD - 1);
    return (m >= LEADER_SRRIP_MIN);
}

void InitReplacementState() {
    // Initialize RRPV array
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Init SHiP-lite & streaming tables
    for (uint32_t i = 0; i < SIG_SIZE; i++) {
        SHCT[i]     = 1;  // weakly-neutral
        SD_last[i]  = 0;
        SD_count[i] = 0;
    }
    // Init PSEL
    PSEL = PSEL_INIT;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim search
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
    uint32_t cpu,
    uint32_t set,
    uint32_t way,
    uint64_t paddr,
    uint64_t PC,
    uint64_t victim_addr,
    uint32_t type,
    uint8_t hit
) {
    uint32_t sig    = Signature(PC);
    uint32_t blk_id = uint32_t(paddr >> 6);

    // Streaming detection (simple +1 stride)
    if (blk_id == SD_last[sig] + 1) {
        if (SD_count[sig] < STREAM_THRESH) SD_count[sig]++;
    } else {
        SD_count[sig] = 0;
    }
    SD_last[sig] = blk_id;

    bool is_stream = (SD_count[sig] >= STREAM_THRESH);

    // Hit processing
    if (hit) {
        // Always promote on hit
        RRPV[set][way] = 0;
        // Train SHCT
        if (SHCT[sig] < 3) SHCT[sig]++;

        // Update PSEL in leader sets
        if (is_leader_srrip(set)) {
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (is_leader_bip(set)) {
            if (PSEL > 0) PSEL--;
        }
    }
    else {
        // Miss insertion
        uint8_t new_rrpv;
        // 1) Bypass true streams
        if (is_stream) {
            new_rrpv = MAX_RRPV;
        }
        // 2) PC-hot lines => highest priority
        else if (SHCT[sig] >= 2) {
            new_rrpv = 0;
        }
        else {
            // Determine policy: leader or follower
            bool use_srrip;
            if (is_leader_bip(set)) {
                use_srrip = false;
            } else if (is_leader_srrip(set)) {
                use_srrip = true;
            } else {
                use_srrip = (PSEL >= PSEL_TH);
            }
            // Insert
            if (use_srrip) {
                new_rrpv = INIT_RRPV;
            } else {
                // Bimodal insertion: long RRPV
                new_rrpv = MAX_RRPV;
            }
        }
        RRPV[set][way] = new_rrpv;

        // Punish cold PCs
        if (SHCT[sig] > 0) SHCT[sig]--;
    }
}

void PrintStats() {
    // no extra stats
}

void PrintStats_Heartbeat() {
    // no extra stats
}