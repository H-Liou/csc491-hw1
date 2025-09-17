#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: PC signatures ---
#define SHIP_SIG_BITS 12 // 4096 entries
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_CTR_BITS 2  // 2-bit outcome counter

struct SHIPEntry {
    uint16_t signature; // lower SHIP_SIG_BITS of PC
    uint8_t counter;    // 2 bits
};

SHIPEntry ship_table[1 << SHIP_SIG_BITS]; // 4096 entries

// Per-block signature for update
uint16_t block_signature[LLC_SETS][LLC_WAYS];

// --- Streaming detector: Per-set, 2-bit counter, last address ---
uint64_t last_addr[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set
#define STREAM_THRESHOLD 3

// --- RRIP state ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_signature, 0, sizeof(block_signature));
    memset(rrpv, 3, sizeof(rrpv));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Streaming detector update ---
inline void update_streaming(uint32_t set, uint64_t paddr) {
    uint64_t last = last_addr[set];
    uint64_t delta = (last == 0) ? 0 : (paddr > last ? paddr - last : last - paddr);
    // Detect monotonic stride: delta == block size (64B), or small stride
    if (last != 0 && (delta == 64 || delta == 128)) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_addr[set] = paddr;
}

// --- Find victim: RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Update replacement state ---
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
    // --- Streaming detector ---
    update_streaming(set, paddr);

    // --- SHiP signature ---
    uint16_t sig = PC & SHIP_SIG_MASK;
    block_signature[set][way] = sig;

    // --- Streaming bypass ---
    if (stream_ctr[set] >= STREAM_THRESHOLD) {
        // streaming detected: bypass block (do not insert, set RRPV=3)
        rrpv[set][way] = 3;
        return;
    }

    // --- SHiP-lite insertion policy ---
    uint8_t ctr = ship_table[sig].counter;
    uint8_t ins_rrpv = (ctr >= 2) ? 1 : 3; // high reuse: insert at RRPV=1, else distant (3)

    if (hit) {
        rrpv[set][way] = 0; // promote on hit
        // update SHiP counter: increment if not max
        if (ship_table[sig].counter < 3) ship_table[sig].counter++;
    } else {
        rrpv[set][way] = ins_rrpv;
        // update SHiP counter: decay if not min
        if (ship_table[sig].counter > 0) ship_table[sig].counter--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= STREAM_THRESHOLD)
            streaming_sets++;
    std::cout << "Sets with streaming detected: " << streaming_sets << "/" << LLC_SETS << std::endl;

    uint32_t high_reuse = 0;
    for (uint32_t i = 0; i < (1 << SHIP_SIG_BITS); ++i)
        if (ship_table[i].counter >= 2)
            high_reuse++;
    std::cout << "SHiP signatures with high reuse: " << high_reuse << "/" << (1 << SHIP_SIG_BITS) << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and SHiP reuse distribution
}