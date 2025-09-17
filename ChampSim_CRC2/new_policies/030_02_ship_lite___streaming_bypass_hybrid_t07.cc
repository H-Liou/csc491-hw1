#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit PC signatures per block + 2-bit outcome counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_TABLE_ENTRIES 2048
uint8_t ship_counter[SHIP_TABLE_ENTRIES]; // 2 bits per entry
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block

// RRIP: 2 bits per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set, 2-bit counter + last address
uint8_t stream_ctr[LLC_SETS];
uint64_t last_addr[LLC_SETS];
#define STREAM_THRESHOLD 3

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_counter, 1, sizeof(ship_counter)); // Neutral starting value
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Streaming detector update ---
inline bool update_streaming(uint32_t set, uint64_t paddr) {
    uint64_t last = last_addr[set];
    uint64_t delta = (last == 0) ? 0 : (paddr > last ? paddr - last : last - paddr);

    if (last != 0 && (delta == 64 || delta == 128)) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_addr[set] = paddr;
    return (stream_ctr[set] >= STREAM_THRESHOLD);
}

// --- Signature hash function ---
inline uint16_t ship_sig_hash(uint64_t PC) {
    // Simple: lower SHIP_SIG_BITS from PC + CRC
    return (uint16_t)((PC ^ champsim_crc2(PC, SHIP_SIG_BITS)) & (SHIP_TABLE_ENTRIES - 1));
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
    // RRIP victim selection
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
    // Streaming detector update
    bool streaming = update_streaming(set, paddr);

    // SHiP-lite signature hash
    uint16_t sig = ship_sig_hash(PC);

    // On hit: promote block, update SHiP
    if (hit) {
        rrpv[set][way] = 0;
        // Positive reinforcement: increment counter, saturate at 3
        if (ship_counter[sig] < 3) ship_counter[sig]++;
    } else {
        ship_signature[set][way] = sig;

        // If streaming detected, bypass: do not cache the block (simulate by RRPV=3, never promote)
        if (streaming) {
            rrpv[set][way] = 3;
            // Negative reinforcement: decrement SHiP counter
            if (ship_counter[sig] > 0) ship_counter[sig]--;
            return;
        }

        // Otherwise, use SHiP outcome counter to pick insertion depth
        uint8_t ctr = ship_counter[sig];
        // High reuse: insert at RRPV=0, moderate at 2, low at 3
        if (ctr >= 2)
            rrpv[set][way] = 0; // Likely reused soon
        else if (ctr == 1)
            rrpv[set][way] = 2; // Moderate reuse
        else
            rrpv[set][way] = 3; // Dead-on-arrival
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= STREAM_THRESHOLD)
            streaming_sets++;
    uint32_t hot_signatures = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_ENTRIES; ++i)
        if (ship_counter[i] >= 2)
            hot_signatures++;
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid statistics:" << std::endl;
    std::cout << "Sets with streaming detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Hot PC signatures: " << hot_signatures << "/" << SHIP_TABLE_ENTRIES << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and hot signature count
}