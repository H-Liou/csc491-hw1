#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
static const uint32_t SHIP_SIG_BITS = 6; // 64-entry signature table
static const uint32_t SHIP_SIG_ENTRIES = 1 << SHIP_SIG_BITS;
struct SHIPEntry {
    uint8_t reuse_ctr; // 2 bits
};
static SHIPEntry ship_table[SHIP_SIG_ENTRIES];

// Per-line signature tracking
static uint8_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// --- RRIP metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Streaming detector ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All lines: RRPV=3 (long re-use distance)
    memset(line_sig, 0, sizeof(line_sig));
    memset(ship_table, 0, sizeof(ship_table));
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

// --- SHiP signature hash ---
inline uint8_t GetSignature(uint64_t PC) {
    // Simple hash: lower SHIP_SIG_BITS of PC XOR upper bits
    return ((PC >> 2) ^ (PC >> (SHIP_SIG_BITS + 2))) & (SHIP_SIG_ENTRIES - 1);
}

// --- Find victim (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
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

    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);

    // --- On hit: promote to MRU, update SHiP outcome ---
    if (hit) {
        rrpv[set][way] = 0;
        // Positive outcome: increment reuse counter (max 3)
        if (ship_table[line_sig[set][way]].reuse_ctr < 3)
            ship_table[line_sig[set][way]].reuse_ctr++;
        return;
    }

    // --- On eviction: negative outcome for previous block ---
    uint8_t victim_sig = line_sig[set][way];
    if (ship_table[victim_sig].reuse_ctr > 0)
        ship_table[victim_sig].reuse_ctr--;

    // --- Streaming-aware bypass ---
    if (streaming) {
        // Insert at distant RRPV (bypass effect)
        rrpv[set][way] = 3;
        line_sig[set][way] = sig;
        return;
    }

    // --- SHiP-guided insertion depth ---
    // If signature has high reuse, insert at RRPV=0 (MRU)
    // If low reuse, insert at RRPV=3 (LRU)
    // If moderate, insert at RRPV=2
    uint8_t reuse = ship_table[sig].reuse_ctr;
    if (reuse == 3) {
        rrpv[set][way] = 0;
    } else if (reuse == 2) {
        rrpv[set][way] = 2;
    } else {
        rrpv[set][way] = 3;
    }
    line_sig[set][way] = sig;
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SHiP-SA Policy: SHiP-lite + Streaming-Aware Bypass\n";
    // SHiP table histogram
    uint32_t ship_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        ship_hist[ship_table[i].reuse_ctr]++;
    std::cout << "SHiP reuse counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
    // Streaming counter histogram
    uint32_t stream_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        stream_hist[stream_ctr[i]]++;
    std::cout << "Streaming counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}