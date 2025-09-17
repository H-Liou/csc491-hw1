#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP RRPV ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Streaming Detector: per-set, last 2 address deltas ---
uint64_t stream_last_addr[LLC_SETS];
int64_t stream_last_delta[LLC_SETS];
uint8_t stream_conf[LLC_SETS]; // 2-bit confidence

// --- Per-set SHiP-lite table (8 entries per set) ---
#define SHIP_SET_SIG_BITS 3 // 8 entries per set
#define SHIP_SIG_TABLE_SIZE (1 << SHIP_SET_SIG_BITS)
uint8_t ship_sig_table[LLC_SETS][SHIP_SIG_TABLE_SIZE]; // 2 bits per entry
uint8_t ship_sig[LLC_SETS][LLC_WAYS]; // store last signature per line

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Init to distant RRPV
    memset(stream_last_addr, 0, sizeof(stream_last_addr));
    memset(stream_last_delta, 0, sizeof(stream_last_delta));
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(ship_sig_table, 1, sizeof(ship_sig_table)); // Start optimistic
    memset(ship_sig, 0, sizeof(ship_sig));
}

// --- SHiP-lite signature hash (PC & set-local 3 bits) ---
inline uint8_t GetSignature(uint64_t PC) {
    return champsim_crc2(PC, 0) & (SHIP_SIG_TABLE_SIZE - 1);
}

// --- Streaming detector: update per-set on every fill ---
inline bool StreamingActive(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - stream_last_addr[set];
    if (stream_last_addr[set] != 0) {
        // If delta matches previous delta, increase confidence
        if (delta == stream_last_delta[set]) {
            if (stream_conf[set] < 3) ++stream_conf[set];
        } else {
            if (stream_conf[set] > 0) --stream_conf[set];
        }
    }
    stream_last_delta[set] = delta;
    stream_last_addr[set] = paddr;
    return (stream_conf[set] >= 3);
}

// --- SRRIP victim selection ---
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
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
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
    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);

    // --- On hit: mark MRU and update SHiP ---
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_sig_table[set][sig] < 3) ++ship_sig_table[set][sig];
        return;
    }

    // --- On fill: update streaming detector ---
    bool streaming = StreamingActive(set, paddr);

    // --- Save signature for victim ---
    ship_sig[set][way] = sig;

    // --- Insertion policy ---
    if (streaming) {
        // Streaming detected: bypass (insert at distant RRPV)
        rrpv[set][way] = 3;
    } else if (ship_sig_table[set][sig] == 0) {
        // No reuse history: insert at distant RRPV
        rrpv[set][way] = 3;
    } else if (ship_sig_table[set][sig] == 3) {
        // Strong reuse: insert at MRU
        rrpv[set][way] = 0;
    } else {
        // Moderate reuse: insert at middle RRPV
        rrpv[set][way] = 2;
    }
}

// --- On eviction: update SHiP table ---
void OnEviction(
    uint32_t set, uint32_t way
) {
    uint8_t sig = ship_sig[set][way];
    // If not reused (RRPV==3), decrement SHiP counter
    if (rrpv[set][way] == 3) {
        if (ship_sig_table[set][sig] > 0)
            --ship_sig_table[set][sig];
    }
}

// --- Periodic decay of SHiP counters and streaming confidence ---
void DecayMetadata() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t i = 0; i < SHIP_SIG_TABLE_SIZE; ++i)
            if (ship_sig_table[set][i] > 0)
                --ship_sig_table[set][i];
        if (stream_conf[set] > 0)
            --stream_conf[set];
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "S3H Policy: SRRIP + Streaming Detector + Per-set SHiP Hybrid\n";
}
void PrintStats_Heartbeat() {}