#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES 1024 // 2^10 entries
static uint8_t ship_sig[LLC_SETS][LLC_WAYS]; // 5 bits per line
static uint8_t ship_ctr[SHIP_SIG_ENTRIES];   // 2 bits per signature

// --- RRPV metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Streaming detector metadata ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Helper: get SHiP signature from PC ---
inline uint16_t GetSignature(uint64_t PC) {
    // Use lower SHIP_SIG_BITS bits of CRC32 of PC for signature
    return champsim_crc32(PC) & ((1 << SHIP_SIG_BITS) - 1);
}

// --- Initialization ---
void InitReplacementState() {
    memset(ship_sig, 0, sizeof(ship_sig));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Initialize to weakly reused
    memset(rrpv, 3, sizeof(rrpv));
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

    // --- Get signature for this access ---
    uint16_t sig = GetSignature(PC);

    // --- On hit: promote to MRU and update SHiP counter ---
    if (hit) {
        rrpv[set][way] = 0;
        // Update SHiP counter for the signature (max 3)
        if (ship_ctr[sig] < 3) ship_ctr[sig]++;
        return;
    }

    // --- On fill: record signature in line ---
    ship_sig[set][way] = sig;

    // --- Streaming-aware bypass ---
    if (streaming) {
        rrpv[set][way] = 3; // insert at distant RRPV (bypass)
        return;
    }

    // --- SHiP insertion policy ---
    // If signature counter is high (>=2), insert at MRU (RRPV=0)
    // Else, insert at SRRIP default (RRPV=2)
    if (ship_ctr[sig] >= 2)
        rrpv[set][way] = 0;
    else
        rrpv[set][way] = 2;
}

// --- On eviction: update SHiP counter for dead block ---
void OnEviction(uint32_t set, uint32_t way) {
    uint8_t sig = ship_sig[set][way];
    if (ship_ctr[sig] > 0) ship_ctr[sig]--;
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SHiP-SB Policy: SHiP-Lite + Streaming-Aware Bypass\n";
    // Print histogram of SHiP counters
    uint32_t ship_hist[4] = {0,0,0,0};
    for (int i=0; i<SHIP_SIG_ENTRIES; ++i)
        ship_hist[ship_ctr[i]]++;
    std::cout << "SHiP counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
    // Print histogram of streaming counters
    uint32_t stream_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        stream_hist[stream_ctr[i]]++;
    std::cout << "Streaming counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}

// --- Integration: call OnEviction in simulator when a block is evicted ---
// For example, in the block replacement logic, call:
// OnEviction(set, victim_way);