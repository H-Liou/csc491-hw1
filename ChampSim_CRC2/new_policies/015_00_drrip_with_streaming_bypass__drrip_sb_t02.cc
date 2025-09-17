#include <vector>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE    1
#define LLC_SETS    (NUM_CORE * 2048)
#define LLC_WAYS    16

// RRIP parameters
static const uint8_t  MAX_RRPV     = 3;     // 2-bit [0..3]
static const uint8_t  SRRIP_RRPV   = MAX_RRPV - 1; // =2
// DRRIP parameters
static const uint16_t PSEL_MAX     = 1023;  // 10-bit counter
static uint16_t       PSEL;                // [0..PSEL_MAX]

// Streaming detector per-core
static uint64_t last_miss_addr;
static uint64_t last_delta;
static uint8_t  stream_ctr; // 2-bit saturating [0..3]

// Per-line RRPV
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

void InitReplacementState() {
    // Initialize RRPVs to max; reset DRRIP PSEL; reset stream detector
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    PSEL           = PSEL_MAX / 2;
    last_miss_addr = 0;
    last_delta     = 0;
    stream_ctr     = 2; // neutral
}

// Find a victim by standard RRIP: look for RRPV==MAX, else age
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
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

// Update replacement state
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
    // Determine leader-set roles
    // We'll use 64-set windows: [0..31] SRRIP leaders, [32..63] BRRIP leaders
    uint32_t bucket = set & 0x3F;
    bool is_srrip_leader = (bucket < 32);
    bool is_brrip_leader = (bucket >= 32 && bucket < 64);

    if (hit) {
        // On hit: promote to MRU
        RRPV[set][way] = 0;
        // Update DRRIP policy votes
        if (is_srrip_leader) {
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (is_brrip_leader) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // MISS path --------------------------------------------------
    // 1) Streaming detection
    uint64_t delta = (paddr >= last_miss_addr) ? (paddr - last_miss_addr)
                                               : (last_miss_addr - paddr);
    if (delta == last_delta && delta != 0) {
        // reinforce streaming
        if (stream_ctr > 0) stream_ctr--;
    } else {
        // break streaming
        if (stream_ctr < 3) stream_ctr++;
    }
    last_delta     = delta;
    last_miss_addr = paddr;
    bool is_stream = (stream_ctr <= 1);

    // 2) Bypass streaming blocks entirely
    if (is_stream) {
        RRPV[set][way] = MAX_RRPV;
        return;
    }

    // 3) DRRIP insertion decision
    uint16_t mid = PSEL_MAX >> 1;
    if (is_srrip_leader) {
        // SRRIP policy
        RRPV[set][way] = SRRIP_RRPV;
    } else if (is_brrip_leader) {
        // BRRIP policy: 1/32 chance of "SRRIP" insert
        if ((rand() & 0x1F) == 0) {
            RRPV[set][way] = SRRIP_RRPV;
        } else {
            RRPV[set][way] = MAX_RRPV;
        }
    } else {
        // follower sets: use global PSEL to pick
        if (PSEL > mid) {
            // follow SRRIP
            RRPV[set][way] = SRRIP_RRPV;
        } else {
            // follow BRRIP
            if ((rand() & 0x1F) == 0) {
                RRPV[set][way] = SRRIP_RRPV;
            } else {
                RRPV[set][way] = MAX_RRPV;
            }
        }
    }
}

void PrintStats() {
    // no additional stats
}

void PrintStats_Heartbeat() {
    // no-op
}