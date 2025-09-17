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

// Replacement state
static uint8_t RRPV[LLC_SETS][LLC_WAYS];
static uint8_t SHCT[SIG_SIZE];                 // 2-bit saturating counters per PC signature
static uint32_t SD_last_addr[SIG_SIZE];        // last block address per signature
static uint8_t SD_count[SIG_SIZE];             // sequential stride counter per signature

// Helper: hash PC to signature
static inline uint32_t Signature(uint64_t PC) {
    // simple xor-fold and mask
    return uint32_t((PC ^ (PC >> 12)) & SIG_MASK);
}

void InitReplacementState() {
    // Initialize RRPVs and tables
    for (uint32_t set = 0; set < LLC_SETS; set++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[set][w] = MAX_RRPV;
        }
    }
    for (uint32_t i = 0; i < SIG_SIZE; i++) {
        SHCT[i] = 1;           // weakly neutral
        SD_last_addr[i] = 0;
        SD_count[i] = 0;
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
    // SRRIP victim selection: find RRPV == MAX_RRPV
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // age all lines
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
    uint32_t sig = Signature(PC);
    uint32_t blk_id = uint32_t(paddr >> 6);

    // Update streaming detector
    if (blk_id == SD_last_addr[sig] + 1) {
        if (SD_count[sig] < STREAM_THRESH) SD_count[sig]++;
    } else {
        SD_count[sig] = 0;
    }
    SD_last_addr[sig] = blk_id;

    if (hit) {
        // On hit: promote to RRPV = 0, train SHCT
        RRPV[set][way] = 0;
        if (SHCT[sig] < 3) SHCT[sig]++;
    } else {
        // On miss: insert new line at 'way'
        uint8_t rrpv_new;
        bool is_stream = (SD_count[sig] >= STREAM_THRESH);
        bool predict_reuse = (SHCT[sig] >= 2);

        if (is_stream) {
            // Buffered bypass: make very likely to be evicted
            rrpv_new = MAX_RRPV;
        } else if (predict_reuse) {
            // Strong reuse: bring to RRPV=0
            rrpv_new = 0;
        } else {
            // default weak insertion
            rrpv_new = INIT_RRPV;
            if (rrpv_new > MAX_RRPV) rrpv_new = MAX_RRPV;
        }
        RRPV[set][way] = rrpv_new;
        // Optionally punish cold PCs slightly
        if (!predict_reuse && SHCT[sig] > 0) SHCT[sig]--;
    }
}

void PrintStats() {
    // nothing to print
}

void PrintStats_Heartbeat() {
    // nothing to print
}