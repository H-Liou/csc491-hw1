#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP per-block RRPV (2 bits per block) ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: 2-bit per set, last address/delta ---
uint8_t stream_ctr[LLC_SETS];
uint64_t last_addr[LLC_SETS];
uint64_t last_delta[LLC_SETS];

// --- SHiP-lite: 128-entry per-set signature table (2 bits per entry) ---
#define SHIP_SIG_PER_SET 128
uint8_t ship_sig[LLC_SETS][SHIP_SIG_PER_SET]; // 2 bits per signature

// --- Utility: extract PC signature (7 bits) ---
inline uint8_t GetPCSig(uint64_t PC) {
    return (PC ^ (PC >> 7) ^ (PC >> 13)) & (SHIP_SIG_PER_SET - 1);
}

// --- Periodic decay for SHIP counters ---
uint64_t access_counter = 0;
const uint64_t DECAY_PERIOD = 100000;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(ship_sig, 1, sizeof(ship_sig)); // Initialize to weak bias
}

// --- Find victim: standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find a block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment RRPV of all blocks if no victim found
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
    access_counter++;

    // --- Streaming detector: update on fill (miss only) ---
    if (!hit) {
        uint64_t delta = (last_addr[set] == 0) ? 0 : (paddr - last_addr[set]);
        if (last_addr[set] != 0 && delta == last_delta[set] && delta != 0) {
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
        last_delta[set] = delta;
        last_addr[set] = paddr;
    }

    // --- SHiP-lite: update signature predictor ---
    uint8_t sig = GetPCSig(PC);

    if (hit) {
        // On hit: strengthen outcome (increase counter up to 3), promote block
        if (ship_sig[set][sig] < 3)
            ship_sig[set][sig]++;
        rrpv[set][way] = 0; // Promote reused block
        return;
    } else {
        // On miss: slightly weaken outcome (decrement counter down to 0)
        if (ship_sig[set][sig] > 0)
            ship_sig[set][sig]--;
    }

    // --- Streaming bypass logic ---
    bool streaming = (stream_ctr[set] >= 2);
    if (streaming) {
        // Streaming: bypass by inserting at distant RRPV=3
        rrpv[set][way] = 3;
        return;
    }

    // --- SHiP-guided insertion ---
    if (ship_sig[set][sig] <= 1) {
        // Weak outcome (low reuse): insert at distant RRPV=3
        rrpv[set][way] = 3;
    } else {
        // Strong outcome (high reuse): insert at SRRIP default RRPV=2
        rrpv[set][way] = 2;
    }

    // --- Periodic decay for SHIP counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t i = 0; i < SHIP_SIG_PER_SET; ++i)
                if (ship_sig[s][i] > 0)
                    ship_sig[s][i]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite SRRIP + Streaming Bypass: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << "/" << LLC_SETS << std::endl;

    uint32_t strong_sig = 0, weak_sig = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t i = 0; i < SHIP_SIG_PER_SET; ++i)
            if (ship_sig[s][i] >= 2)
                strong_sig++;
            else
                weak_sig++;
    std::cout << "Strong PC signatures: " << strong_sig << std::endl;
    std::cout << "Weak PC signatures: " << weak_sig << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and signature histogram
}