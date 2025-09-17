#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Per-line state: lower 2 bits=RRPV, next 4 bits=signature
static uint8_t repl_state[LLC_SETS][LLC_WAYS];
// Signature history counter table (SHCT): 16 entries of 2-bit counters [0..3]
static uint8_t SHCT[16];

// Streaming detector per core
static uint64_t last_addr[NUM_CORE];
static uint64_t last_delta[NUM_CORE];

void InitReplacementState() {
    // Initialize RRPV = max (3), signature zero, SHCT = 2 (weakly reusable)
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            repl_state[s][w] = (3u & 0x3);
        }
    }
    for (int i = 0; i < 16; i++) SHCT[i] = 2;
    for (uint32_t c = 0; c < NUM_CORE; c++) {
        last_addr[c] = 0;
        last_delta[c] = 0;
    }
}

// Helper to extract RRPV
static inline uint8_t GET_RRPV(uint8_t s) { return s & 0x3; }
// Helper to extract signature
static inline uint8_t GET_SIG(uint8_t s) { return (s >> 2) & 0xF; }
// Pack sig (4b) and rrpv (2b)
static inline uint8_t PACK(uint8_t sig, uint8_t rrpv) { return ((sig & 0xF) << 2) | (rrpv & 0x3); }

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // SRRIP victim selection: find way with RRPV=3, else increment all and retry
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (GET_RRPV(repl_state[set][w]) == 3) {
                return w;
            }
        }
        // increment all RRPVs (<3)
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            uint8_t r = GET_RRPV(repl_state[set][w]);
            if (r < 3) {
                uint8_t sig = GET_SIG(repl_state[set][w]);
                repl_state[set][w] = PACK(sig, r + 1);
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
    // Compute signature from PC (xor high bits)
    uint8_t sig = ((PC >> 2) ^ (PC >> 7)) & 0xF;

    // Streaming detection: check if delta repeats
    uint64_t delta = (last_addr[cpu] == 0 ? 0 : (paddr - last_addr[cpu]));
    bool streaming = (delta != 0 && delta == last_delta[cpu]);
    last_delta[cpu] = delta;
    last_addr[cpu] = paddr;

    if (hit) {
        // Hit: find the block, reset RRPV, increment SHCT
        uint8_t old = repl_state[set][way];
        uint8_t osig = GET_SIG(old);
        // update SHCT[osig]
        if (SHCT[osig] < 3) SHCT[osig]++;
        // reset RRPV
        repl_state[set][way] = PACK(osig, 0);
    } else {
        // Miss insertion: first update SHCT of evicted block
        // victim_addr is the evicted physical addr; find its signature stored
        uint8_t ev_sig = GET_SIG(repl_state[set][way]);
        // If the evicted line never had a hit since insertion (RRPV>0), treat as dead -> decrement
        if (GET_RRPV(repl_state[set][way]) != 0) {
            if (SHCT[ev_sig] > 0) SHCT[ev_sig]--;
        }
        // Now insert new block at same way
        uint8_t new_rrpv;
        if (streaming) {
            // streaming: deprioritize (max dist)
            new_rrpv = 3;
        } else {
            // use SHCT to choose insertion depth: high confidence -> near-fresh else distant
            new_rrpv = (SHCT[sig] >= 2 ? 1 : 3);
        }
        repl_state[set][way] = PACK(sig, new_rrpv);
    }
}

void PrintStats() {
    // No extra stats
}

void PrintStats_Heartbeat() {
    // No heartbeat stats
}