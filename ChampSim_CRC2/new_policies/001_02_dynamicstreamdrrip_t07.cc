#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
static const uint8_t MAX_RRPV   = 3;
static const uint8_t INIT_RRPV  = 2;

// Streaming detector parameters
static const uint32_t SIG_SIZE     = 1024;
static const uint32_t SIG_MASK     = (SIG_SIZE - 1);
static const uint8_t  STREAM_THRESH= 3;

// BRRIP (Bimodal) parameters
static const uint32_t BIP_TH       = 32;     // 1/32th low RRPV insert
// DRRIP duel parameters
static const uint16_t PSEL_MAX     = 1023;
static const uint16_t PSEL_INIT    = 512;

// Replacement metadata
static uint8_t  RRPV[LLC_SETS][LLC_WAYS];
static uint16_t PSEL;
static uint32_t BRRIP_counter;
static bool     leader_SRRIP[LLC_SETS];
static bool     leader_BRRIP[LLC_SETS];
// Streaming detector tables
static uint32_t SD_last_addr[SIG_SIZE];
static uint8_t  SD_count[SIG_SIZE];

// Helper: hash PC to signature
static inline uint32_t Signature(uint64_t PC) {
    return uint32_t((PC ^ (PC >> 12)) & SIG_MASK);
}

void InitReplacementState() {
    // Initialize RRPVs to far away (likely to be evicted first)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Initialize streaming detector
    for (uint32_t i = 0; i < SIG_SIZE; i++) {
        SD_last_addr[i] = 0;
        SD_count[i]     = 0;
    }
    // Initialize DRRIP selector
    PSEL           = PSEL_INIT;
    BRRIP_counter  = 0;
    // Mark leader sets: every 32nd set is SRRIP leader, offset by 16 for BRRIP
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        if ((s & 31) == 0) {
            leader_SRRIP[s] = true;
            leader_BRRIP[s] = false;
        } else if ((s & 31) == 16) {
            leader_SRRIP[s] = false;
            leader_BRRIP[s] = true;
        } else {
            leader_SRRIP[s] = false;
            leader_BRRIP[s] = false;
        }
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
    // SRRIP-style victim selection
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Age all lines if none are at MAX_RRPV
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
    // 1) Update streaming detector for this PC signature
    uint32_t sig    = Signature(PC);
    uint32_t blk_id = uint32_t(paddr >> 6);
    if (blk_id == SD_last_addr[sig] + 1) {
        if (SD_count[sig] < STREAM_THRESH) {
            SD_count[sig]++;
        }
    } else {
        SD_count[sig] = 0;
    }
    SD_last_addr[sig] = blk_id;

    // 2) On hit: strong promotion and DRRIP feedback
    if (hit) {
        // Promote to RRPV=0
        RRPV[set][way] = 0;
        // Adjust PSEL in leader sets
        if (leader_SRRIP[set] && PSEL < PSEL_MAX) {
            PSEL++;
        } else if (leader_BRRIP[set] && PSEL > 0) {
            PSEL--;
        }
        return;
    }

    // 3) On miss: insertion policy
    bool is_stream = (SD_count[sig] >= STREAM_THRESH);
    uint8_t rrpv_new;
    if (is_stream) {
        // Bypass stream: insert at MAX_RRPV
        rrpv_new = MAX_RRPV;
    } else {
        // Decide SRRIP vs BRRIP for this set
        bool use_SRRIP;
        if (leader_SRRIP[set]) {
            use_SRRIP = true;
        } else if (leader_BRRIP[set]) {
            use_SRRIP = false;
        } else {
            use_SRRIP = (PSEL >= (PSEL_INIT));
        }
        if (use_SRRIP) {
            rrpv_new = INIT_RRPV;
        } else {
            // BRRIP (bimodal): only 1/BIP_TH get INIT_RRPV
            if ((BRRIP_counter++ & (BIP_TH - 1)) == 0) {
                rrpv_new = INIT_RRPV;
            } else {
                rrpv_new = MAX_RRPV;
            }
        }
    }
    RRPV[set][way] = rrpv_new;
}

void PrintStats() {
    // nothing to print
}

void PrintStats_Heartbeat() {
    // nothing to print
}