#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP: 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Dead-block: 2-bit counter per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// SHiP-lite: 512-entry signature table (5-bit index), 2-bit outcome counter
#define SHIP_SIG_SIZE 512
uint8_t ship_sigctr[SHIP_SIG_SIZE];

// Per-block 2-bit last outcome (for feedback)
uint8_t ship_outcome[LLC_SETS][LLC_WAYS];
uint16_t ship_signature[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set, 3-bit monotonicity counter + last address
uint8_t stream_monotonic[LLC_SETS];
uint64_t stream_last_addr[LLC_SETS];

// Thresholds
#define STREAM_THRESH 5
#define SHIP_HOT 2

// Helper: signature hash
inline uint16_t GetSignature(uint64_t PC) {
    return champsim_crc2(PC, 0) & (SHIP_SIG_SIZE - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(ship_sigctr, 1, sizeof(ship_sigctr));
    memset(ship_outcome, 0, sizeof(ship_outcome));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(stream_monotonic, 0, sizeof(stream_monotonic));
    memset(stream_last_addr, 0, sizeof(stream_last_addr));
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Prefer dead-block, cold signature
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3 || ship_outcome[set][way] == 0)
            return way;

    // RRIP victim search
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
}

// Update replacement state
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
    // --- Streaming detector update ---
    uint64_t last_addr = stream_last_addr[set];
    uint8_t mon = stream_monotonic[set];
    if (last_addr) {
        uint64_t delta = (paddr > last_addr) ? paddr - last_addr : last_addr - paddr;
        if (delta > 0 && delta < 1024) { // Small stride
            if (mon < 7) mon++;
        } else {
            if (mon > 0) mon--;
        }
    }
    stream_last_addr[set] = paddr;
    stream_monotonic[set] = mon;

    // --- SHiP signature ---
    uint16_t sig = GetSignature(PC);

    // On hit: promote to MRU, update SHiP and dead-block
    if (hit) {
        rrpv[set][way] = 0;
        // Feedback for SHiP
        ship_sigctr[sig] = (ship_sigctr[sig] < 3) ? ship_sigctr[sig] + 1 : 3;
        ship_outcome[set][way] = SHIP_HOT;
        ship_signature[set][way] = sig;
        // Dead-block reset
        dead_ctr[set][way] = 0;
        return;
    }

    // On miss/fill: assign SHiP signature, update counters
    ship_signature[set][way] = sig;
    ship_outcome[set][way] = ship_sigctr[sig];

    // Insert depth decision
    uint8_t ins_rrpv = 3; // default distant (cache-friendlier for streaming)
    if (ship_sigctr[sig] >= SHIP_HOT)
        ins_rrpv = 2; // hot signature, earlier reuse

    // Streaming: bypass or force distant insertion if monotonicity high
    if (stream_monotonic[set] >= STREAM_THRESH)
        ins_rrpv = 3; // treat as streaming

    // Dead-block: predicted dead, force distant
    if (dead_ctr[set][way] == 3)
        ins_rrpv = 3;

    rrpv[set][way] = ins_rrpv;

    // Dead-block counter update (evicted without reuse)
    if (dead_ctr[set][way] < 3)
        dead_ctr[set][way]++;
    else
        dead_ctr[set][way] = 3; // saturate

    // On fill, reset dead counter if not predicted dead
    if (ins_rrpv != 3)
        dead_ctr[set][way] = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Dead-block counter histogram
    uint64_t db_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            db_hist[dead_ctr[s][w]]++;
    std::cout << "SHiP-LSDH: Dead-block counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << db_hist[i] << " ";
    std::cout << std::endl;

    // SHiP signature counter histogram
    uint64_t sig_hist[4] = {0};
    for (int i = 0; i < SHIP_SIG_SIZE; ++i)
        sig_hist[ship_sigctr[i]]++;
    std::cout << "SHiP-LSDH: SHiP signature histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << sig_hist[i] << " ";
    std::cout << std::endl;

    // Streaming monotonicity
    uint64_t stream_hist[8] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        stream_hist[stream_monotonic[s]]++;
    std::cout << "SHiP-LSDH: Streaming monotonicity histogram: ";
    for (int i = 0; i < 8; ++i)
        std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: dead counters and streaming monotonicity
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] > 0)
                dead_ctr[s][w]--;
        if (stream_monotonic[s] > 0)
            stream_monotonic[s]--;
    }
}