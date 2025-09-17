#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- Metadata Structures ----
// 2 bits RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 6-bit PC signature per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS];

// SHCT: 2-bit counter per signature, 64 entries
#define SHCT_ENTRIES 64
uint8_t shct[SHCT_ENTRIES];

// Streaming detector: 2-bit confidence, last_addr, last_delta per set
uint8_t stream_conf[LLC_SETS];
uint64_t stream_last_addr[LLC_SETS];
int16_t stream_last_delta[LLC_SETS];

// ---- Helper: Hash PC to 6-bit signature ----
inline uint8_t pc_to_sig(uint64_t PC) {
    return (uint8_t)((PC ^ (PC >> 10) ^ (PC >> 20)) & 0x3F);
}

// ---- Initialization ----
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All blocks start distant
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(shct, 1, sizeof(shct)); // Neutral: 1/3
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(stream_last_addr, 0, sizeof(stream_last_addr));
    memset(stream_last_delta, 0, sizeof(stream_last_delta));
}

// ---- Streaming detector ----
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

// ---- Find victim ----
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

// ---- Update replacement state ----
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
    // --- Streaming detection ---
    bool is_streaming = detect_streaming(set, paddr);

    // --- Signature extraction ---
    uint8_t sig = pc_to_sig(PC);

    // --- On hit: mark reuse, update SHCT ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Update SHCT: increment (max 3) for the block's signature
        uint8_t prev_sig = pc_sig[set][way];
        if (shct[prev_sig] < 3) shct[prev_sig]++;
        return;
    }

    // --- On fill: choose insertion depth ---
    // Streaming bypass: do not fill if streaming detected
    if (is_streaming) {
        rrpv[set][way] = 3; // If must fill, insert at distant
        pc_sig[set][way] = sig;
        return;
    }

    // Bias insertion depth by SHCT outcome counter
    uint8_t ins_rrpv = (shct[sig] >= 2) ? 0 : 3; // High SHCT: MRU, else distant
    rrpv[set][way] = ins_rrpv;
    pc_sig[set][way] = sig;

    // On fill, decay outcome counter for victim's previous signature to learn dead blocks
    uint8_t prev_sig = pc_sig[set][way];
    if (shct[prev_sig] > 0) shct[prev_sig]--;
}

// ---- Print end-of-simulation statistics ----
void PrintStats() {
    std::cout << "SHiP-Lite Signature Insertion Policy + Streaming Bypass: Final statistics." << std::endl;
    // Optionally print SHCT histogram, streaming confidence distribution
}

// ---- Print periodic (heartbeat) statistics ----
void PrintStats_Heartbeat() {
    // Optionally print SHCT histogram, streaming confidence
}