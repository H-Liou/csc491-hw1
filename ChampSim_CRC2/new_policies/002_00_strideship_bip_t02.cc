#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRIP parameters
static const uint8_t MAX_RRPV   = 3;
static const uint8_t INIT_RRPV  = 2;

// SHiP-lite signature table
static const uint32_t SIG_SIZE  = 2048;
static const uint32_t SIG_MASK  = (SIG_SIZE - 1);
static uint8_t        SHCT[SIG_SIZE];  // 2-bit saturating counters

// Stride detector tables
static const uint32_t STRIDE_SIZE   = 512;
static const uint32_t STRIDE_MASK   = (STRIDE_SIZE - 1);
static const uint8_t  STRIDE_THRESH = 2;
static uint32_t       SD_last_blk[STRIDE_SIZE];
static int32_t        SD_last_stride[STRIDE_SIZE];
static uint8_t        SD_count[STRIDE_SIZE];

// Bimodal Insertion Policy counter
static const uint32_t BIP_TH       = 32;
static uint32_t       BIP_counter;

// Replacement metadata
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Helper: simple hash of PC to index
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 12)) & mask);
}

void InitReplacementState() {
    // Initialize RRPVs to far-away
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Reset SHCT counters
    for (uint32_t i = 0; i < SIG_SIZE; i++) {
        SHCT[i] = 0;
    }
    // Reset stride detector
    for (uint32_t i = 0; i < STRIDE_SIZE; i++) {
        SD_last_blk[i]    = 0;
        SD_last_stride[i] = 0;
        SD_count[i]       = 0;
    }
    // Reset BIP counter
    BIP_counter = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu, 
    uint32_t set, 
    const BLOCK *current_set, 
    uint64_t PC, 
    uint64_t paddr, 
    uint32_t type
) {
    // SRRIP-style victim selection
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Age all if none at MAX_RRPV
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
    // 1) Stride detection
    uint32_t sidx    = PCIndex(PC, STRIDE_MASK);
    uint32_t blk_id  = uint32_t(paddr >> 6);
    int32_t  stride  = int32_t(blk_id) - int32_t(SD_last_blk[sidx]);
    if (stride == SD_last_stride[sidx]) {
        if (SD_count[sidx] < STRIDE_THRESH) {
            SD_count[sidx]++;
        }
    } else {
        SD_last_stride[sidx] = stride;
        SD_count[sidx]       = 1;
    }
    SD_last_blk[sidx] = blk_id;
    bool is_stream    = (SD_count[sidx] >= STRIDE_THRESH);

    // 2) On hit: promote and train SHCT
    uint32_t sig = PCIndex(PC, SIG_MASK);
    if (hit) {
        // Strong promotion
        RRPV[set][way] = 0;
        // Increment reuse counter (saturate at 3)
        if (SHCT[sig] < 3) {
            SHCT[sig]++;
        }
        return;
    }

    // 3) On miss: choose insertion RRPV
    uint8_t new_rrpv;
    if (is_stream) {
        // Bypass streaming scans
        new_rrpv = MAX_RRPV;
    } else {
        // SHiP-based reuse check
        if (SHCT[sig] >= 2) {
            // Known good producer → SRRIP insert
            new_rrpv = INIT_RRPV;
        } else {
            // Cold or unknown → Bimodal insertion
            if ((BIP_counter++ & (BIP_TH - 1)) == 0) {
                new_rrpv = INIT_RRPV;
            } else {
                new_rrpv = MAX_RRPV;
            }
        }
    }
    RRPV[set][way] = new_rrpv;
}

void PrintStats() {
    // no statistics
}

void PrintStats_Heartbeat() {
    // no heartbeat stats
}