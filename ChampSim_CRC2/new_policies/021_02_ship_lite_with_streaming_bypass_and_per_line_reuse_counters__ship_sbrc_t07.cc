#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 5-bit PC signature table, 2-bit outcome counter per entry
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES 1024
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
struct SHIPEntry {
    uint8_t counter; // 2-bit saturating
};
SHIPEntry ship_table[SHIP_SIG_ENTRIES];

// Per-block metadata: 2-bit RRPV, 2-bit reuse_ctr, 5-bit PC signature
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t reuse_ctr; // 2 bits
    uint8_t sig;       // 5 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Streaming detector: last address and delta per set (simple monotonic stream detector)
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_conf; // 2 bits, saturating
};
StreamDetect stream_meta[LLC_SETS];

// Helper: compressed PC signature
inline uint8_t GetSig(uint64_t PC) {
    return champsim_crc2(PC) & SHIP_SIG_MASK;
}

// Streaming detector: returns true if stream detected in this set
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_meta[set];
    int64_t delta = paddr - sd.last_addr;
    bool is_stream = false;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_conf < 3) sd.stream_conf++;
        } else {
            if (sd.stream_conf > 0) sd.stream_conf--;
        }
        if (sd.stream_conf >= 2) is_stream = true;
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return is_stream;
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(ship_table, 0, sizeof(ship_table));
    memset(stream_meta, 0, sizeof(stream_meta));
}

// Find victim in the set: prefer invalid, then reuse_ctr==0, else RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // 1. Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // 2. Prefer blocks with reuse_ctr==0 (dead-block approximation)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (meta[set][way].reuse_ctr == 0)
            return way;

    // 3. RRIP victim search
    uint8_t RRPV_MAX = 3;
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == RRPV_MAX)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < RRPV_MAX)
                meta[set][way].rrpv++;
    }
    return 0;
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
    // --- Streaming detector update ---
    bool is_stream = IsStreaming(set, paddr);

    // --- On hit: promote to MRU, increment reuse counter ---
    if (hit) {
        meta[set][way].rrpv = 0;
        if (meta[set][way].reuse_ctr < 3)
            meta[set][way].reuse_ctr++;
        // Update SHiP outcome counter for the block's signature
        uint8_t sig = meta[set][way].sig;
        if (ship_table[sig].counter < 3)
            ship_table[sig].counter++;
        return;
    }

    // --- On miss/fill: choose insertion depth via SHiP or streaming ---
    uint8_t sig = GetSig(PC);
    meta[set][way].sig = sig;
    uint8_t ins_rrpv = 3; // Default: distant

    if (is_stream) {
        // Streaming: bypass if possible (do not insert), else insert at distant
        ins_rrpv = 3;
    } else {
        // Use SHiP signature outcome counter
        ins_rrpv = (ship_table[sig].counter >= 2) ? 0 : 3;
    }
    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].reuse_ctr = 1; // Assume live on fill

    // --- On victim: update SHiP outcome counter for the signature of evicted block
    // If evicted block was not reused (reuse_ctr==0), decrement
    uint8_t victim_sig = meta[set][way].sig;
    if (meta[set][way].reuse_ctr == 0 && ship_table[victim_sig].counter > 0)
        ship_table[victim_sig].counter--;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print SHiP outcome histogram and streaming detector
    uint32_t ship_hi = 0, ship_lo = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_table[i].counter >= 2) ship_hi++;
        else ship_lo++;
    }
    uint32_t stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].stream_conf >= 2) stream_sets++;
    std::cout << "SHiP-SBRC: SHiP_hi=" << ship_hi << ", SHiP_lo=" << ship_lo
              << ", streaming sets=" << stream_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age reuse counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].reuse_ctr > 0)
                meta[s][w].reuse_ctr--;
}