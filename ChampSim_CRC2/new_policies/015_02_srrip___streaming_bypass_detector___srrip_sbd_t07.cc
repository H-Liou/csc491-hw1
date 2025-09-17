#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP Metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Streaming Bypass Detector Metadata ---
// For each set: last two physical block addresses and streaming flag
static uint64_t last_addr[LLC_SETS][2]; // 2 × 8 bytes × 2048 = 32 KiB
static uint8_t streaming_flag[LLC_SETS]; // 1 byte × 2048 = 2 KiB

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(last_addr, 0, sizeof(last_addr));
    memset(streaming_flag, 0, sizeof(streaming_flag));
}

// --- Find victim: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment RRPVs (aging)
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
    // Only check for streaming on insert (miss)
    uint64_t block_addr = paddr & ~0x3F; // block address (assuming 64B lines)
    uint8_t is_stream = 0;
    if (!hit) {
        uint64_t delta1 = (last_addr[set][0]) ? block_addr - last_addr[set][0] : 0;
        uint64_t delta2 = (last_addr[set][1]) ? last_addr[set][0] - last_addr[set][1] : 0;
        // If both deltas are equal and small (±64B or ±128B), mark streaming
        if (delta1 == delta2 &&
            (delta1 == 64 || delta1 == -64 || delta1 == 128 || delta1 == -128))
            is_stream = 1;
        streaming_flag[set] = is_stream;
        // Update history
        last_addr[set][1] = last_addr[set][0];
        last_addr[set][0] = block_addr;
    }
    // --- Insertion policy ---
    // On hit: promote to MRU
    if (hit) {
        rrpv[set][way] = 0;
        return;
    }
    // On miss: streaming sets insert at RRPV=3 (distant), non-streaming at RRPV=2
    if (streaming_flag[set]) {
        // Optionally: bypass insertion for streaming sets (leave block as invalid)
        rrpv[set][way] = 3;
    } else {
        rrpv[set][way] = 2;
    }
}

// --- Print statistics ---
void PrintStats() {
    uint32_t stream_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        stream_sets += streaming_flag[i];
    std::cout << "SRRIP-SBD Policy\n";
    std::cout << "Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
}

// --- Heartbeat stats ---
void PrintStats_Heartbeat() {
    // Optional: print periodic streaming set count
}