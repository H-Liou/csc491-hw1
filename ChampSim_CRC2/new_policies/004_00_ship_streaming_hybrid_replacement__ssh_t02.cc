#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 6-bit PC signature per line, 2-bit outcome counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS) // 64
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6 bits per line
uint8_t ship_table[SHIP_TABLE_SIZE];        // 2 bits per signature

// Streaming detector: per-set last address, delta, streaming flag
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 2 bits
    bool is_streaming;
};
StreamDetect stream_detect[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_table, 1, sizeof(ship_table)); // optimistic: assume some reuse
    memset(stream_detect, 0, sizeof(stream_detect));
}

// --- Streaming detector ---
// Returns true if streaming detected for this set
bool DetectStreaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_detect[set];
    int64_t delta = paddr - sd.last_addr;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_count < 3) ++sd.stream_count;
        } else {
            if (sd.stream_count > 0) --sd.stream_count;
        }
        sd.is_streaming = (sd.stream_count >= 2);
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return sd.is_streaming;
}

// --- SHiP signature hash ---
inline uint8_t GetSignature(uint64_t PC) {
    // Simple CRC or lower bits
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & (SHIP_TABLE_SIZE - 1);
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
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
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
    bool streaming = DetectStreaming(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Mark as reused in SHiP table
        if (ship_table[sig] < 3) ++ship_table[sig];
        return;
    }

    // --- On fill ---
    ship_signature[set][way] = sig;

    // Streaming phase: bypass fill (insert at distant RRPV)
    if (streaming) {
        rrpv[set][way] = 3;
        return;
    }

    // SHiP: consult outcome counter
    if (ship_table[sig] == 0) {
        // Dead block: insert at distant RRPV
        rrpv[set][way] = 3;
    } else {
        // Live block: insert at MRU
        rrpv[set][way] = 0;
    }
}

// --- Periodic decay of SHiP table (optional, every N million accesses) ---
void DecaySHIPTable() {
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_table[i] > 0) --ship_table[i];
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SSH Policy: SHiP-lite (PC-based) + Streaming Detector Hybrid\n";
}
void PrintStats_Heartbeat() {}