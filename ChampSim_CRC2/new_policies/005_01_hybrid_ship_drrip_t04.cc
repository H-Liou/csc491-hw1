#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRIP parameters
static const uint8_t MAX_RRPV   = 3;
static const uint8_t INIT_RRPV  = 2;  // SRRIP insertion
static const uint32_t BRRIP_PROB = 32; // 1/32 chance to insert near

// DRRIP PSEL
static const uint16_t PSEL_MAX   = 1023; // 10-bit
static const uint16_t PSEL_INIT  = PSEL_MAX / 2;
static uint16_t       PSEL;

// SHiP-Lite signature predictor
static const uint32_t SHCT_SIZE = 4096;
static const uint32_t SHCT_MASK = (SHCT_SIZE - 1);
static uint8_t        SHCT[SHCT_SIZE];   // 2-bit counters
static const uint8_t  SHCT_MAX = 3;
static const uint8_t  SHCT_INIT= 1;

// Simple stride‐based streaming detector
static const uint32_t STRIDE_SIZE  = 512;
static const uint32_t STRIDE_MASK  = (STRIDE_SIZE - 1);
static const uint8_t  STRIDE_THRESH= 2;
static uint32_t       SD_last_blk[STRIDE_SIZE];
static int32_t        SD_last_stride[STRIDE_SIZE];
static uint8_t        SD_count[STRIDE_SIZE];

// Replacement metadata
static uint8_t RRPV[LLC_SETS][LLC_WAYS];
static uint32_t brip_ctr = 0;

// Hash PC to small index
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    // Initialize RRPVs to long (cold)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Init PSEL
    PSEL = PSEL_INIT;
    // Init SHCT
    for (uint32_t i = 0; i < SHCT_SIZE; i++) {
        SHCT[i] = SHCT_INIT;
    }
    // Init stride detector
    for (uint32_t i = 0; i < STRIDE_SIZE; i++) {
        SD_last_blk[i]    = 0;
        SD_last_stride[i] = 0;
        SD_count[i]       = 0;
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu, uint32_t set,
    const BLOCK *current_set,
    uint64_t PC, uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
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
    // 1) Streaming detection
    uint32_t sidx   = PCIndex(PC, STRIDE_MASK);
    uint32_t blk_id = uint32_t(paddr >> 6);
    int32_t  stride = int32_t(blk_id) - int32_t(SD_last_blk[sidx]);
    if (stride == SD_last_stride[sidx]) {
        if (SD_count[sidx] < STRIDE_THRESH) SD_count[sidx]++;
    } else {
        SD_last_stride[sidx] = stride;
        SD_count[sidx]       = 1;
    }
    SD_last_blk[sidx] = blk_id;
    bool is_stream    = (SD_count[sidx] >= STRIDE_THRESH);

    // 2) SHiP signature
    uint32_t sig = PCIndex(PC, SHCT_MASK);

    if (hit) {
        // Hit: promote strongly
        RRPV[set][way] = 0;
        // Train SHiP
        if (SHCT[sig] < SHCT_MAX) SHCT[sig]++;
        return;
    }

    // 3) On miss: update PSEL on leader sets
    uint32_t mod = set & 63;
    if (mod == 0) {
        // SRRIP leader suffered a miss => reduce trust
        if (PSEL > 0) PSEL--;
    } else if (mod == 1) {
        // BRRIP leader suffered a miss => increase trust
        if (PSEL < PSEL_MAX) PSEL++;
    }

    // 4) Decide insertion RRPV
    uint8_t new_rrpv;
    if (is_stream) {
        // Bypass streaming
        new_rrpv = MAX_RRPV;
    } else if (SHCT[sig] >= 2) {
        // Predicted hot by SHiP
        new_rrpv = 0;
    } else {
        // Choose policy: leaders force SRRIP/BRRIP, others by PSEL
        bool use_srrip;
        if (mod == 0) {
            use_srrip = true;
        } else if (mod == 1) {
            use_srrip = false;
        } else {
            use_srrip = (PSEL >= (PSEL_MAX >> 1));
        }
        if (use_srrip) {
            new_rrpv = INIT_RRPV;
        } else {
            // BRRIP: mostly cold, occasionally near
            if ((brip_ctr++ & (BRRIP_PROB - 1)) == 0) {
                new_rrpv = INIT_RRPV;
            } else {
                new_rrpv = MAX_RRPV;
            }
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