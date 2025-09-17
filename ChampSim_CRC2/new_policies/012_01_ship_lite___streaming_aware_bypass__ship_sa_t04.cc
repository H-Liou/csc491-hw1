#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits per line

// --- SHiP-lite table: 1024 entries, 6-bit PC signature, 2-bit counter ---
static const uint32_t SHIP_TABLE_SIZE = 1024;
static uint8_t ship_counter[SHIP_TABLE_SIZE]; // 2 bits per entry

// --- Per-line signature ---
static uint8_t line_sig[LLC_SETS][LLC_WAYS];  // 6 bits per line

// --- Streaming detector ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_ctr[LLC_SETS];          // 2 bits per set

// --- Dead-block decay epoch (for SHiP counter aging) ---
static uint64_t access_epoch = 0;
static const uint64_t DECAY_PERIOD = 100000;

// --- Helper: hash PC to 6-bit signature ---
inline uint8_t GetSignature(uint64_t PC) {
    // Use CRC32 and fold to 6 bits
    return champsim_crc32(PC) & 0x3F;
}

// --- Helper: index into SHiP table ---
inline uint32_t GetSHIPIndex(uint8_t sig) {
    // Simple direct-mapped for 1024 entries
    return sig;
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

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));      // All lines: RRPV=3 (long re-use distance)
    memset(ship_counter, 1, sizeof(ship_counter)); // Initialize to neutral value
    memset(line_sig, 0, sizeof(line_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    access_epoch = 0;
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
    access_epoch++;

    // --- Streaming detection ---
    bool streaming = IsStreaming(set, paddr);

    // --- SHiP counter decay (aging) ---
    if (access_epoch % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
            if (ship_counter[i] > 0) ship_counter[i]--;
    }

    uint8_t sig = GetSignature(PC);
    uint32_t ship_idx = GetSHIPIndex(sig);

    // --- On hit: promote to MRU, mark SHiP as reused ---
    if (hit) {
        rrpv[set][way] = 0;
        // Increment SHiP counter (max 3)
        if (ship_counter[line_sig[set][way]] < 3)
            ship_counter[line_sig[set][way]]++;
        return;
    }

    // --- On eviction: update SHiP outcome for victim ---
    // If victim_addr is valid (not zero), decrement SHiP counter for its signature
    uint8_t victim_sig = line_sig[set][way];
    if (ship_counter[victim_sig] > 0)
        ship_counter[victim_sig]--;

    // --- Streaming-aware bypass ---
    if (streaming) {
        // Insert at distant RRPV (bypass effect)
        rrpv[set][way] = 3;
        line_sig[set][way] = sig;
        return;
    }

    // --- SHiP-guided insertion depth ---
    if (ship_counter[ship_idx] >= 2) {
        // Good reuse: insert at MRU
        rrpv[set][way] = 0;
    } else {
        // Poor reuse: insert at distant RRPV
        rrpv[set][way] = 3;
    }
    line_sig[set][way] = sig;
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SHiP-SA Policy: SHiP-lite + Streaming-Aware Bypass\n";
    // SHiP counter histogram
    uint32_t ship_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        ship_hist[ship_counter[i]]++;
    std::cout << "SHiP counter histogram: ";
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