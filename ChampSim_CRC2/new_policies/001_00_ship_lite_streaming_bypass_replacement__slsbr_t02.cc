#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2 bits RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature per set
uint8_t pc_sig[LLC_SETS][LLC_WAYS];
uint8_t pc_sig_ctr[LLC_SETS][64]; // 6-bit index, 2-bit counter

// Streaming detector: 2-bit confidence, 8-bit last_addr, 8-bit last_delta per set
uint8_t stream_conf[LLC_SETS];
uint64_t stream_last_addr[LLC_SETS];
int16_t stream_last_delta[LLC_SETS];

// --- Helper: get PC signature (6 bits) ---
inline uint8_t get_pc_sig(uint64_t PC) {
    return (PC >> 2) & 0x3F;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All blocks start distant
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(pc_sig_ctr, 1, sizeof(pc_sig_ctr)); // Start at weak reuse
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(stream_last_addr, 0, sizeof(stream_last_addr));
    memset(stream_last_delta, 0, sizeof(stream_last_delta));
}

// --- Streaming detector update ---
inline bool detect_streaming(uint32_t set, uint64_t paddr) {
    int16_t delta = (int16_t)(paddr - stream_last_addr[set]);
    bool monotonic = (delta == stream_last_delta[set]) && (delta != 0);

    if (monotonic) {
        if (stream_conf[set] < 3) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    stream_last_delta[set] = delta;
    stream_last_addr[set] = paddr;

    // Streaming if confidence high
    return (stream_conf[set] >= 2);
}

// --- Find victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection: Pick block with RRPV==3, else increment all and retry
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3) {
                return way;
            }
        }
        // No block at RRPV==3, increment all (except max)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3) rrpv[set][way]++;
        }
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
    bool is_streaming = detect_streaming(set, paddr);

    // --- SHiP-lite predictor ---
    uint8_t sig = get_pc_sig(PC);

    // --- On hit: increment outcome counter, protect block ---
    if (hit) {
        if (pc_sig_ctr[set][sig] < 3) pc_sig_ctr[set][sig]++;
        rrpv[set][way] = 0; // Most recently used
        return;
    }

    // --- On fill: update PC signature ---
    pc_sig[set][way] = sig;

    // --- On eviction: if block was not reused, decay outcome counter ---
    static uint64_t access_counter = 0;
    access_counter++;
    if ((access_counter & 0x7FFF) == 0) { // Every 32K accesses, decay all counters
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t i = 0; i < 64; ++i)
                if (pc_sig_ctr[s][i] > 0) pc_sig_ctr[s][i]--;
    }

    // --- Streaming: bypass or insert distant ---
    if (is_streaming) {
        // Bypass: do not insert block (simulate by setting RRPV=3, block will be replaced quickly)
        rrpv[set][way] = 3;
        return;
    }

    // --- SHiP-lite: insertion depth based on outcome counter ---
    uint8_t ctr = pc_sig_ctr[set][sig];
    if (ctr >= 2) {
        rrpv[set][way] = 1; // Protect more aggressively
    } else {
        rrpv[set][way] = 3; // Insert at distant
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SLSBR Replacement Policy: Final statistics." << std::endl;
}

void PrintStats_Heartbeat() {
    // Optional: print streaming confidence histogram, SHiP counter stats, etc.
}