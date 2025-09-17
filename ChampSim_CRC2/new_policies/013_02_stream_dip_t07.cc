#include <vector>
#include <cstdint>
#include <algorithm>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE        1
#define LLC_SETS        (NUM_CORE * 2048)
#define LLC_WAYS        16

// RRIP parameters
static const uint8_t  MAX_RRPV        = 3;    // 2-bit RRPV [0..3]
static const uint8_t  SRRIP_INS       = MAX_RRPV - 1; // insert near-MRU
static const uint8_t  BIP_INS         = MAX_RRPV;     // LIP insertion (bypass)

// DIP parameters
static const uint32_t NUM_LEADER      = 64;
static const uint32_t BIP_LEADER      = 32;
static const uint32_t SRRIP_LEADER    = 32;
static const uint16_t PSEL_MAX        = 1023;
static const uint16_t PSEL_INIT       = PSEL_MAX / 2;
static const uint16_t PSEL_THRESHOLD  = PSEL_MAX / 2;

// Streaming detector per set
static uint64_t       LastAddr[LLC_SETS];
static uint64_t       LastDelta[LLC_SETS];
static uint8_t        StreamConf[LLC_SETS];

// DIP state
static uint8_t        LeaderType[LLC_SETS]; // 0=follower,1=BIP,2=SRRIP
static uint16_t       PSEL;                 // [0..PSEL_MAX]

// RRIP state
static uint8_t        RRPV[LLC_SETS][LLC_WAYS];

void InitReplacementState() {
    // Initialize RRPVs and streaming
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
        LastAddr[s]   = 0;
        LastDelta[s]  = 0;
        StreamConf[s] = 0;
        // Assign leader sets [0..31]=BIP, [32..63]=SRRIP, else follower
        if (s < BIP_LEADER) {
            LeaderType[s] = 1;
        } else if (s < (BIP_LEADER + SRRIP_LEADER)) {
            LeaderType[s] = 2;
        } else {
            LeaderType[s] = 0;
        }
    }
    PSEL = PSEL_INIT;
}

// Find a victim by searching for RRPV == MAX_RRPV, aging otherwise
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
        // Age all lines
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] < MAX_RRPV) {
                RRPV[set][w]++;
            }
        }
    }
}

// Update on hit or miss
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
    if (hit) {
        // On hit, promote to MRU
        RRPV[set][way] = 0;
        return;
    }
    // MISS --------------------------------------------------------
    // 1) Streaming detection: need 4 identical deltas
    uint64_t delta = (LastAddr[set] ? paddr - LastAddr[set] : 0);
    if (delta != 0 && delta == LastDelta[set]) {
        StreamConf[set]++;
    } else {
        StreamConf[set] = 0;
    }
    LastDelta[set] = delta;
    LastAddr[set]  = paddr;
    bool is_stream = (StreamConf[set] >= 4);

    // 2) Choose insertion RRPV via DIP + streaming bypass
    uint8_t ins_rrpv;
    if (is_stream) {
        ins_rrpv = MAX_RRPV; // bypass long streams
    }
    else if (LeaderType[set] == 1) {
        // BIP leader
        ins_rrpv = BIP_INS;
    }
    else if (LeaderType[set] == 2) {
        // SRRIP leader
        ins_rrpv = SRRIP_INS;
    }
    else {
        // follower: choose based on PSEL
        if (PSEL >= PSEL_THRESHOLD) {
            ins_rrpv = SRRIP_INS;
        } else {
            ins_rrpv = BIP_INS;
        }
    }
    RRPV[set][way] = ins_rrpv;

    // 3) Update PSEL on misses in leader sets (measure miss-rate)
    if (!is_stream) {
        if (LeaderType[set] == 1) {
            // BIP leader miss => BIP is worse => reward SRRIP by increasing PSEL
            PSEL = std::min<uint16_t>(PSEL + 1, PSEL_MAX);
        }
        else if (LeaderType[set] == 2) {
            // SRRIP leader miss => SRRIP worse => reward BIP by decreasing PSEL
            PSEL = std::max<uint16_t>(PSEL - 1, 0);
        }
    }
}

void PrintStats() {
    // No additional stats
}

void PrintStats_Heartbeat() {
    // No-op
}