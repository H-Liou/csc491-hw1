#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-Lite Metadata ---
// Per line: 6-bit PC signature, 2-bit outcome counter
struct SHIPLine {
    uint8_t pc_sig;    // 6 bits
    uint8_t reuse_cnt; // 2 bits
};
static SHIPLine ship_lines[LLC_SETS][LLC_WAYS];

// --- Streaming Detector Metadata ---
// Per set: last two block addresses + streaming flag
static uint64_t last_addr[LLC_SETS][2]; // 2 × 8 bytes × 2048 = 32 KiB
static uint8_t streaming_flag[LLC_SETS]; // 1 byte × 2048 = 2 KiB

// --- Initialization ---
void InitReplacementState() {
    memset(ship_lines, 0, sizeof(ship_lines));
    memset(last_addr, 0, sizeof(last_addr));
    memset(streaming_flag, 0, sizeof(streaming_flag));
}

// --- Find victim: standard RRIP ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // RRIP victim selection (same as before)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Aging
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
    uint64_t block_addr = paddr & ~0x3F; // 64B lines
    uint8_t is_stream = 0;
    if (!hit) {
        uint64_t delta1 = (last_addr[set][0]) ? block_addr - last_addr[set][0] : 0;
        uint64_t delta2 = (last_addr[set][1]) ? last_addr[set][0] - last_addr[set][1] : 0;
        // Streaming if both deltas equal and small (±64B or ±128B)
        if (delta1 == delta2 &&
            (delta1 == 64 || delta1 == -64 || delta1 == 128 || delta1 == -128))
            is_stream = 1;
        streaming_flag[set] = is_stream;
        last_addr[set][1] = last_addr[set][0];
        last_addr[set][0] = block_addr;
    }

    // --- SHiP-Lite Signature Extraction ---
    uint8_t sig = (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F; // 6 bits

    // --- On hit: update reuse counter, promote to MRU ---
    if (hit) {
        ship_lines[set][way].reuse_cnt = std::min(ship_lines[set][way].reuse_cnt + 1, 3u);
        rrpv[set][way] = 0;
        return;
    }

    // --- Streaming sets: bypass insert entirely (do NOT update line metadata) ---
    if (streaming_flag[set]) {
        // Do not insert; leave block invalid
        rrpv[set][way] = 3;
        // Optionally track that this block was bypassed (no metadata update)
        return;
    }

    // --- SHiP-Lite driven insertion ---
    // If signature reuse_cnt >=2: insert at RRPV=0 (MRU)
    // If reuse_cnt==1: insert at RRPV=1
    // If reuse_cnt==0: insert at RRPV=3 (LRU)
    uint8_t reuse = ship_lines[set][way].reuse_cnt;
    if (reuse >= 2) rrpv[set][way] = 0;
    else if (reuse == 1) rrpv[set][way] = 1;
    else rrpv[set][way] = 3;

    // Update line metadata
    ship_lines[set][way].pc_sig = sig;
    ship_lines[set][way].reuse_cnt = 0; // Reset on new fill
}

// --- Print statistics ---
void PrintStats() {
    uint32_t stream_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        stream_sets += streaming_flag[i];
    std::cout << "SHiP-SB Policy\n";
    std::cout << "Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
}

// --- Heartbeat stats ---
void PrintStats_Heartbeat() {
    // Optional: print periodic streaming set count, reuse stats
}