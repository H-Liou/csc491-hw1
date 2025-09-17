#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE      1
#define LLC_SETS      (NUM_CORE * 2048)
#define LLC_WAYS      16

// RRIP parameters
static const uint8_t  MAX_RRPV       = 3;
static const uint8_t  INSERT_RRPV    = 2;

// DIP parameters
static const uint32_t DUELERS        = 64;    // 32 LRU‐leader + 32 BIP‐leader
static const uint32_t LEADER_QUOTA   = 32;
static const uint16_t PSEL_MAX       = 1023;  // 10‐bit
static const uint16_t PSEL_INIT      = PSEL_MAX/2;
static uint16_t       PSEL;
static uint8_t        isLRULeader[LLC_SETS];
static uint8_t        isBIPLeader[LLC_SETS];

// Per‐line metadata
static uint8_t        RRPV[LLC_SETS][LLC_WAYS];   // 2‐bit RRIP counters
static uint8_t        UseBit[LLC_SETS][LLC_WAYS]; // 1‐bit “was ever hit?”

// PC reuse signature (3‐bit)
static const uint32_t SIG_BITS       = 11;
static const uint32_t SIG_SZ         = (1 << SIG_BITS);
static const uint32_t SIG_MASK       = SIG_SZ - 1;
static const uint8_t  SIG_MAX        = 7;      // 3‐bit max
static uint8_t        SigTable[SIG_SZ];         // 0–7

// Simple PC hash
static inline uint32_t PCIndex(uint64_t PC, uint32_t mask) {
    return uint32_t((PC ^ (PC >> 12) ^ (PC >> 22)) & mask);
}

void InitReplacementState() {
    // Init per‐line RRIP & use bits
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w]   = MAX_RRPV;
            UseBit[s][w] = 0;
        }
    }
    // Init PC‐signature table to middle (3)
    for (uint32_t i = 0; i < SIG_SZ; i++) {
        SigTable[i] = SIG_MAX / 2; // =3
    }
    // Init DIP PSEL and leader sets
    PSEL = PSEL_INIT;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        uint32_t slot = s & (DUELERS - 1);
        isLRULeader[s] = (slot < LEADER_QUOTA);
        isBIPLeader[s] = (slot >= LEADER_QUOTA && slot < 2 * LEADER_QUOTA);
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu, uint32_t set,
    const BLOCK *current_set,
    uint64_t PC, uint64_t paddr,
    uint32_t type
) {
    // 1) Prefer RRPV==MAX && UseBit==0
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV && UseBit[set][w] == 0) {
            return w;
        }
    }
    // 2) Then any RRPV==MAX
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] == MAX_RRPV) {
            return w;
        }
    }
    // 3) Age all, retry
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (RRPV[set][w] < MAX_RRPV) {
            RRPV[set][w]++;
        }
    }
    return GetVictimInSet(cpu, set, current_set, PC, paddr, type);
}

void UpdateReplacementState(
    uint32_t cpu, uint32_t set, uint32_t way,
    uint64_t paddr, uint64_t PC, uint64_t victim_addr,
    uint32_t type, uint8_t hit
) {
    uint32_t sig = PCIndex(PC, SIG_MASK);

    if (hit) {
        // On hit: warm the reuse predictor, reset RRPV, mark used
        if (SigTable[sig] < SIG_MAX) SigTable[sig]++;
        RRPV[set][way]   = 0;
        UseBit[set][way] = 1;
        return;
    }

    // On miss: decay the reuse predictor
    if (SigTable[sig] > 0) SigTable[sig]--;

    // DIP leader updates
    if (isLRULeader[set]) {
        // LRU‐leader got a miss => favor BIP
        if (PSEL > 0) PSEL--;
    } else if (isBIPLeader[set]) {
        // BIP‐leader got a miss => favor LRU
        if (PSEL < PSEL_MAX) PSEL++;
    }

    // Classify PC phase
    uint8_t reuse = SigTable[sig];
    if (reuse <= 1) {
        // streaming => bypass
        RRPV[set][way]   = MAX_RRPV;
        UseBit[set][way] = 0;
    }
    else if (reuse >= 5) {
        // recurrent => promote strongly
        RRPV[set][way]   = 0;
        UseBit[set][way] = 0;
    }
    else {
        // medium => DIP between LRU (always RRPV=0) and BIP
        bool use_lru;
        if (isLRULeader[set])        use_lru = true;
        else if (isBIPLeader[set])   use_lru = false;
        else                          use_lru = (PSEL > (PSEL_MAX/2));

        if (use_lru) {
            // LRU insertion
            RRPV[set][way]   = 0;
        } else {
            // BIP insertion: mostly far, occasionally RRPV=2
            if (PCIndex(PC, 31) == 0) {
                RRPV[set][way] = INSERT_RRPV;
            } else {
                RRPV[set][way] = MAX_RRPV;
            }
        }
        UseBit[set][way] = 0;
    }
}

void PrintStats() {
    std::cout << "PF-DIP PSEL=" << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    // no-op
}