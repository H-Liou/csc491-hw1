#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-Lite metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS];         // 2 bits per line
static uint8_t sig[LLC_SETS][LLC_WAYS];          // 5 bits per line (PC signature)
static uint8_t outcome[LLC_SETS][LLC_WAYS];      // 2 bits per line (reuse counter)

// --- Signature outcome table (indexed by 5-bit signature) ---
static uint8_t sig_table[32];                    // 2 bits per signature

// --- Streaming detector metadata ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_ctr[LLC_SETS];             // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));      // All lines: RRPV=3 (long re-use distance)
    memset(sig, 0, sizeof(sig));
    memset(outcome, 0, sizeof(outcome));
    memset(sig_table, 1, sizeof(sig_table)); // Default: weakly reused
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

// --- Compute 5-bit PC signature ---
inline uint8_t GetSignature(uint64_t PC) {
    // Simple hash: lower 5 bits XOR upper 5 bits
    return ((PC >> 2) ^ (PC >> 13)) & 0x1F;
}

// --- Victim selection (SRRIP method) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
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

    // --- Get current signature ---
    uint8_t signature = GetSignature(PC);

    // --- On hit: promote to MRU, update outcome ---
    if (hit) {
        rrpv[set][way] = 0;
        // Mark outcome as reused
        if (outcome[set][way] < 3) outcome[set][way]++;
        // Update global table
        if (sig_table[sig[set][way]] < 3) sig_table[sig[set][way]]++;
        return;
    }

    // --- On eviction: update outcome table if block was not reused ---
    if (outcome[set][way] == 0) {
        // Block never reused: decrement signature outcome
        if (sig_table[sig[set][way]] > 0) sig_table[sig[set][way]]--;
    }
    // Reset outcome for new block
    outcome[set][way] = 0;

    // --- Streaming-aware bypass ---
    if (streaming) {
        rrpv[set][way] = 3; // Insert at distant RRPV (bypass)
        sig[set][way] = signature;
        return;
    }

    // --- SHiP-Lite insertion: consult signature outcome table ---
    if (sig_table[signature] >= 2) {
        // Frequently reused: insert at RRPV=0 (MRU)
        rrpv[set][way] = 0;
    } else if (sig_table[signature] == 1) {
        // Weakly reused: insert at RRPV=2
        rrpv[set][way] = 2;
    } else {
        // Not reused: insert at RRPV=3
        rrpv[set][way] = 3;
    }
    sig[set][way] = signature;
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SHiP-SB Policy: SHiP-Lite + Streaming-Aware Bypass\n";
    // Print histogram of streaming counters
    uint32_t stream_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        stream_hist[stream_ctr[i]]++;
    std::cout << "Streaming counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
    // Print signature outcome histogram
    uint32_t sig_hist[4] = {0,0,0,0};
    for (int i=0; i<32; ++i) sig_hist[sig_table[i]]++;
    std::cout << "Signature outcome histogram: ";
    for (int i=0; i<4; ++i) std::cout << sig_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}