#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE      1
#define LLC_SETS      (NUM_CORE * 2048)
#define LLC_WAYS      16

// RRIP parameters
static const uint8_t MAX_RRPV      = 3;    // 2-bit RRPV [0..3]
static const uint8_t SRRIP_RRPV    = MAX_RRPV - 1; // 2
static const uint32_t PSEL_MAX     = 1023; // 10-bit

// DRRIP set-dueling
static const uint32_t NUM_LEADERS  = 64;
static uint16_t PSEL; // [0..PSEL_MAX]

// PC signature + stream history
static const uint32_t SIG_BITS     = 12;
static const uint32_t SIG_SZ       = (1 << SIG_BITS); // 4096
struct SigEntry {
    uint8_t  reuse_ctr : 4;   // [0..15]
    uint8_t  str_conf  : 2;   // stream confidence
    uint32_t last_delta;      // last observed delta
};
static SigEntry SigTable[SIG_SZ];

// RRIP state per line
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// Simple PC hash to signature index
static inline uint32_t SigIndex(uint64_t PC) {
    return uint32_t((PC ^ (PC >> 13) ^ (PC >> 23)) & (SIG_SZ - 1));
}

// Initialize all metadata
void InitReplacementState() {
    // Initialize RRIP to far (MAX)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Init PSEL to neutral
    PSEL = PSEL_MAX / 2;
    // Init PC signature table: weakly reuse=1, clear stream state
    for (uint32_t i = 0; i < SIG_SZ; i++) {
        SigTable[i].reuse_ctr  = 1;
        SigTable[i].str_conf   = 0;
        SigTable[i].last_delta = 0;
    }
}

// Find victim by standard RRIP aging
uint32_t GetVictimInSet(
    uint32_t cpu, uint32_t set,
    const BLOCK *current_set,
    uint64_t PC, uint64_t paddr, uint32_t type
) {
    // Search for an RRPV == MAX
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // Age all ways
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] < MAX_RRPV) {
                RRPV[set][w]++;
            }
        }
    }
}

// Update on hit or miss
void UpdateReplacementState(
    uint32_t cpu, uint32_t set, uint32_t way,
    uint64_t paddr, uint64_t PC, uint64_t victim_addr,
    uint32_t type, uint8_t hit
) {
    uint32_t idx = SigIndex(PC);
    SigEntry &e = SigTable[idx];

    if (hit) {
        // Promote on hit
        RRPV[set][way] = 0;
        // strengthen reuse counter
        if (e.reuse_ctr < 15) e.reuse_ctr++;
        return;
    }

    // MISS path ---------------------------------------------------
    // 1) Stride-based streaming detection per PC
    uint32_t delta = (e.last_delta == 0 ? 0 :
                     (uint32_t)( (paddr - victim_addr) ));
    if (delta != 0 && delta == e.last_delta) {
        if (e.str_conf < 3) e.str_conf++;
    } else {
        e.str_conf = 0;
    }
    e.last_delta = delta;
    bool is_stream = (e.str_conf >= 3);

    // 2) DRRIP set-dueling decision
    bool leader_srrip = (set < NUM_LEADERS);
    bool leader_brrip = (set >= NUM_LEADERS && set < 2 * NUM_LEADERS);
    bool use_brrip = false;
    if (leader_srrip) {
        use_brrip = false;
    } else if (leader_brrip) {
        use_brrip = true;
    } else {
        use_brrip = (PSEL > (PSEL_MAX / 2));
    }

    // On a miss in leaders, update PSEL
    if (leader_srrip && !is_stream) {
        // SRRIP leader misses vote for SRRIP => increment to favor SRRIP
        if (PSEL < PSEL_MAX) PSEL++;
    } else if (leader_brrip && !is_stream) {
        // BRRIP leader misses vote for BRRIP => decrement to favor BRRIP
        if (PSEL > 0) PSEL--;
    }

    // 3) Compute insertion RRPV
    uint8_t insertion;
    if (is_stream) {
        // bypass on streams
        insertion = MAX_RRPV;
    } else if (e.reuse_ctr >= 12) {
        // hot PC override => MRU
        insertion = 0;
    } else if (use_brrip) {
        // BRRIP: mostly far, occasionally near-MRU
        insertion = ( (rand() & 31) == 0 ? 0 : MAX_RRPV );
    } else {
        // SRRIP: always near-MRU
        insertion = SRRIP_RRPV;
    }
    RRPV[set][way] = insertion;

    // 4) On miss for hot PCs that failed => negative feedback
    if (e.reuse_ctr > 8) {
        e.reuse_ctr--;
    }
}

void PrintStats() {
    // No extra stats
}

void PrintStats_Heartbeat() {
    // No-op
}