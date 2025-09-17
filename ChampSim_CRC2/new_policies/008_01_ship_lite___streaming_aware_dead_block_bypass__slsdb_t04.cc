#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: per-line 4-bit PC signature, per-set 16-entry 2-bit outcome table ---
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 4 bits per line
uint8_t outcome_table[LLC_SETS][16]; // 2 bits per PC signature

// --- Dead-block approximation: per-line 2-bit reuse counter ---
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Streaming detector: per-set, 2-entry delta history, 2-bit streaming counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(outcome_table, 1, sizeof(outcome_table)); // neutral outcome
    memset(reuse_ctr, 0, sizeof(reuse_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
}

// --- Streaming detector update ---
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    bool streaming = false;
    if (last_delta[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) ++stream_ctr[set];
    } else {
        if (stream_ctr[set] > 0) --stream_ctr[set];
    }
    streaming = (stream_ctr[set] >= 2);
    last_delta[set] = delta;
    last_addr[set] = paddr;
    return streaming;
}

// --- Victim selection (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
    static uint8_t rrpv[LLC_SETS][LLC_WAYS];
    // Initialize rrpv on first use
    static bool initialized = false;
    if (!initialized) {
        memset(rrpv, 3, sizeof(rrpv));
        initialized = true;
    }
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
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
    // --- Streaming detection ---
    bool streaming = IsStreaming(set, paddr);

    // --- Compute PC signature ---
    uint8_t sig = (PC ^ (PC >> 4)) & 0xF; // 4 bits

    // --- Dead-block prediction ---
    bool predicted_dead = (reuse_ctr[set][way] == 0);

    // --- Outcome table update ---
    if (hit) {
        if (outcome_table[set][pc_sig[set][way]] < 3)
            outcome_table[set][pc_sig[set][way]]++;
        if (reuse_ctr[set][way] < 3)
            reuse_ctr[set][way]++;
    } else {
        if (outcome_table[set][pc_sig[set][way]] > 0)
            outcome_table[set][pc_sig[set][way]]--;
        if (reuse_ctr[set][way] > 0)
            reuse_ctr[set][way]--;
    }

    // --- Periodic decay of reuse counters (every 4096 fills) ---
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_ctr[s][w] > 0) reuse_ctr[s][w]--;
    }

    // --- On fill ---
    static uint8_t rrpv[LLC_SETS][LLC_WAYS];
    if (hit) {
        rrpv[set][way] = 0; // Promote to MRU
        return;
    }

    pc_sig[set][way] = sig;

    // --- Streaming detected or dead block: bypass or insert at distant RRPV ---
    if (streaming || predicted_dead) {
        rrpv[set][way] = 3; // Bypass or insert at max RRPV
        reuse_ctr[set][way] = 0;
        return;
    }

    // --- SHiP-lite insertion: use outcome table to bias insertion ---
    uint8_t outcome = outcome_table[set][sig];
    if (outcome >= 2) {
        rrpv[set][way] = 1; // Good PC: insert at RRPV=1
        reuse_ctr[set][way] = 2;
    } else {
        rrpv[set][way] = 2; // Poor PC: insert at RRPV=2
        reuse_ctr[set][way] = 1;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SLSDB Policy: SHiP-Lite + Streaming-Aware Dead Block Bypass\n";
    // Print a histogram of outcome_table values for diagnostics
    uint32_t hist[4] = {0,0,0,0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t i = 0; i < 16; ++i)
            hist[outcome_table[s][i]]++;
    std::cout << "Outcome table histogram: ";
    for (int i=0; i<4; ++i) std::cout << hist[i] << " ";
    std::cout << std::endl;
}
void PrintStats_Heartbeat() {}