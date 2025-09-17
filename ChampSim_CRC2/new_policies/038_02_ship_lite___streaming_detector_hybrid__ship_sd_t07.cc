#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: 6-bit PC signature table, 2-bit outcome counter ----
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS) // 64 entries per set, but share globally
#define SHIP_GLOBAL_ENTRIES 8192 // ~13 KiB
struct SHIPEntry {
    uint8_t reuse_ctr; // 2 bits
};
SHIPEntry ship_table[SHIP_GLOBAL_ENTRIES];

// Per-block PC signature
uint8_t block_sig[LLC_SETS][LLC_WAYS];

// ---- Streaming detector: per-set stride and monotonicity ----
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_stride;
    uint8_t stream_count; // 3 bits: up to 7
};
StreamDetect stream_detect[LLC_SETS];

// Streaming threshold for bypass/long-dead insertion
#define STREAM_THRES 5

// Helper: hash PC to SHiP signature
uint16_t GetShipSig(uint64_t PC) {
    // Use CRC or simple hash
    return champsim_crc2(PC) % SHIP_GLOBAL_ENTRIES;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // distant insertion
            block_sig[set][way] = 0;
        }
    for (uint32_t i = 0; i < SHIP_GLOBAL_ENTRIES; ++i)
        ship_table[i].reuse_ctr = 1; // neutral reuse
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        stream_detect[set].last_addr = 0;
        stream_detect[set].last_stride = 0;
        stream_detect[set].stream_count = 0;
    }
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // SRRIP victim: block with RRPV=3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // If none, increment all RRPV
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
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
    // ---- Streaming detector update ----
    int64_t stride = (int64_t)paddr - (int64_t)stream_detect[set].last_addr;
    if (stream_detect[set].last_stride != 0 &&
        stride == stream_detect[set].last_stride) {
        // Monotonic stride continues
        if (stream_detect[set].stream_count < 7)
            stream_detect[set].stream_count++;
    } else {
        // Stride breaks; reset
        stream_detect[set].stream_count = 0;
    }
    stream_detect[set].last_addr = paddr;
    stream_detect[set].last_stride = stride;

    // ---- SHiP-lite update ----
    uint16_t sig = GetShipSig(PC);

    // On hit: block reused, increment SHiP counter
    if (hit) {
        if (ship_table[sig].reuse_ctr < 3)
            ship_table[sig].reuse_ctr++;
    } else {
        // On miss: victim block's SHiP counter is decremented if not reused
        uint8_t victim_sig = block_sig[set][way];
        if (ship_table[victim_sig].reuse_ctr > 0)
            ship_table[victim_sig].reuse_ctr--;
    }

    // Assign signature to new block
    block_sig[set][way] = sig;

    // ---- Insertion logic: streaming detector + SHiP ----
    // If streaming detected, force distant (or bypass if possible)
    if (stream_detect[set].stream_count >= STREAM_THRES) {
        // Streaming: insert as long-dead
        rrpv[set][way] = 3;
    } else {
        // SHiP-guided insertion
        if (ship_table[sig].reuse_ctr >= 2) {
            // High reuse: insert as MRU (rrpv=0)
            rrpv[set][way] = 0;
        } else if (ship_table[sig].reuse_ctr == 1) {
            // Moderate: insert as mid (rrpv=1)
            rrpv[set][way] = 1;
        } else {
            // Low reuse: insert as distant (rrpv=2)
            rrpv[set][way] = 2;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int mru_blocks = 0, distant_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (stream_detect[set].stream_count >= STREAM_THRES)
            streaming_sets++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) mru_blocks++;
            if (rrpv[set][way] == 2 || rrpv[set][way] == 3) distant_blocks++;
        }
    }
    std::cout << "SHiP-SD Policy: SHiP-Lite + Streaming Detector Hybrid" << std::endl;
    std::cout << "MRU blocks: " << mru_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_detect[set].stream_count >= STREAM_THRES)
            streaming_sets++;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}