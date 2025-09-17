#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16

// RRPV parameters
static const uint8_t MAX_RRPV   = 3;
static const uint8_t INIT_RRPV  = 2;    // BIP "thick" insertion

// DIP parameters
static const uint16_t PSEL_MAX  = 1023; // 10‐bit
static const uint16_t PSEL_INIT = 512;
static uint16_t       PSEL;

// Dead-Block Predictor (DBP) table
static const uint32_t DBP_SIZE = 4096;
static const uint32_t DBP_MASK = (DBP_SIZE - 1);
static uint8_t        DBP[DBP_SIZE];    // 2-bit counters

// Simple stride‐based streaming detector
static const uint32_t STRIDE_SIZE = 512;
static const uint32_t STRIDE_MASK = (STRIDE_SIZE - 1);
static const uint8_t  STRIDE_THRESH= 2;
static uint32_t       SD_last_blk[STRIDE_SIZE];
static int32_t        SD_last_stride[STRIDE_SIZE];
static uint8_t        SD_count[STRIDE_SIZE];

// Replacement metadata
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Utility: hash PC to small index
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & mask);
}

void InitReplacementState() {
    PSEL = PSEL_INIT;
    // initialize RRPVs
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // clear DBP
    for (uint32_t i = 0; i < DBP_SIZE; i++) {
        DBP[i] = 0;
    }
    // clear stride detector
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
    // Standard SRRIP eviction: find RRPV==MAX, else age all
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
    // 1) Stride‐based streaming detection
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
    bool is_stream = (SD_count[sidx] >= STRIDE_THRESH);

    // 2) Dead‐Block Predictor index
    uint32_t sig = PCIndex(PC, DBP_MASK);

    if (hit) {
        // on hit: promote strongly
        RRPV[set][way] = 0;
        // train DBP
        if (DBP[sig] < 3) DBP[sig]++;
        // update PSEL on leader sets
        if ((set & 63) == 0) {         // BIP leader
            if (PSEL < PSEL_MAX) PSEL++;
        } else if ((set & 63) == 1) {  // LIP leader
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // 3) On miss: choose insertion RRPV
    uint8_t new_rrpv;
    if (DBP[sig] >= 2) {
        // predicted hot → front priority
        new_rrpv = 0;
    } else if (is_stream) {
        // bypass streams
        new_rrpv = MAX_RRPV;
    } else {
        // DIP: choose BIP vs LIP by PSEL
        if (PSEL >= (PSEL_MAX >> 1)) {
            // BIP: low‐prob thick insertion
            static uint32_t bip_ctr = 0;
            if ((bip_ctr++ & 31) == 0) {
                new_rrpv = INIT_RRPV;
            } else {
                new_rrpv = MAX_RRPV;
            }
        } else {
            // LIP: always low priority
            new_rrpv = MAX_RRPV;
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