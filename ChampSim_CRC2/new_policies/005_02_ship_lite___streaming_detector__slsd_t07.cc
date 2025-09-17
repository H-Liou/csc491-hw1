#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 4-bit PC signatures -> 2-bit outcome counters (2048 entries) ---
#define SHIP_SIG_BITS 4
#define SHIP_TABLE_ENTRIES 2048
uint8_t ship_reuse[SHIP_TABLE_ENTRIES]; // 2 bits per entry

// --- Streaming detector: 8 bits per set for last delta, 4 bits for repeat count ---
uint8_t stream_last_delta[LLC_SETS];
uint8_t stream_repeat_ctr[LLC_SETS];

// --- RRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Helper: hash PC to signature ---
inline uint16_t GetShipSignature(uint64_t PC) {
    return ((PC >> 2) ^ (PC >> 11)) & ((1 << SHIP_SIG_BITS)-1); // 4 bits, then mod table size
}

// --- Helper: map signature to table entry ---
inline uint16_t ShipTableIndex(uint16_t sig) {
    return sig ^ (sig << 5) ^ (sig << 9) & (SHIP_TABLE_ENTRIES-1);
}

// --- Initialization ---
void InitReplacementState() {
    memset(ship_reuse, 1, sizeof(ship_reuse)); // start neutral (01)
    memset(rrpv, 3, sizeof(rrpv));
    memset(stream_last_delta, 0, sizeof(stream_last_delta));
    memset(stream_repeat_ctr, 0, sizeof(stream_repeat_ctr));
}

// --- Streaming detector: should we bypass on this fill? ---
bool ShouldBypassStreaming(uint32_t set, uint64_t paddr) {
    static uint64_t last_addr[LLC_SETS] = {0};
    uint8_t delta = (uint8_t)((paddr >> 6) - (last_addr[set] >> 6)); // block address delta
    last_addr[set] = paddr;

    if (delta == 0) return false; // ignore same block
    if (stream_last_delta[set] == delta) {
        if (stream_repeat_ctr[set] < 15) stream_repeat_ctr[set]++;
    } else {
        stream_last_delta[set] = delta;
        stream_repeat_ctr[set] = 1;
    }
    // If delta repeated >=6 times, treat as streaming pattern
    return (stream_repeat_ctr[set] >= 6);
}

// --- Find victim: RRIP (no dead-block counters), pick way with RRPV==3 ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // RRIP victim selection: pick block with RRPV==3, else increment all and retry
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
    // --- SHiP-lite signature ---
    uint16_t sig = GetShipSignature(PC);
    uint16_t idx = ShipTableIndex(sig);

    // --- On hit: set RRPV=0, increment outcome counter ---
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_reuse[idx] < 3) ship_reuse[idx]++;
        return;
    }

    // --- Streaming detector: bypass if streaming detected ---
    if (ShouldBypassStreaming(set, paddr)) {
        // Do not cache: treat as immediate eviction (no insertion)
        rrpv[set][way] = 3; // if hardware requires fill, make it instantly evictable
        return;
    }

    // --- On fill: decide insertion depth based on SHiP-lite outcome counter ---
    if (ship_reuse[idx] >= 2) {
        rrpv[set][way] = 2; // signature has reuse, retain longer
    } else {
        rrpv[set][way] = 3; // low reuse, short retention
    }
    // No dead-block counter needed

    // --- On eviction: decay outcome counter if not reused ---
    // This is implicit: if block not hit before eviction, decrement signature counter
    // But we don't know victim's PC directly, so optionally: if way was at RRPV==3 (not reused), decay
    if (rrpv[set][way] == 3 && ship_reuse[idx] > 0) ship_reuse[idx]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Detector (SLSD) statistics." << std::endl;
    // Optionally print outcome counter histogram
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming detector activity, SHiP reuse histogram
}