#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit PC signature, 2-bit outcome counter
#define SHIP_SIG_BITS 6
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
struct SHIPEntry {
    uint8_t reuse_ctr; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// Per-block metadata: RRPV (2 bits), dead-counter (2 bits), PC signature (6 bits)
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t dead_ctr;  // 2 bits
    uint8_t sig;       // 6 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Streaming detector: last address and delta per set (simple monotonic stream detector)
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_conf; // 2 bits, saturating
};
StreamDetect stream_meta[LLC_SETS];

// Helper: SHiP signature extraction
inline uint8_t get_sig(uint64_t PC) {
    // Use lower SHIP_SIG_BITS of PC CRC
    return champsim_crc2(PC, 0) & SHIP_SIG_MASK;
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
    memset(stream_meta, 0, sizeof(stream_meta));
    memset(ship_table, 0, sizeof(ship_table));
}

// Find victim in the set (prefer invalid, then dead blocks, then RRIP)
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

    // 2. Prefer dead blocks (dead_ctr==0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (meta[set][way].dead_ctr == 0)
            return way;

    // 3. RRIP victim search
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
                meta[set][way].rrpv++;
    }
    return 0; // Should not reach
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

    // --- SHiP signature extraction ---
    uint8_t sig = get_sig(PC);

    // --- On hit: promote to MRU, reset dead-counter, update SHiP outcome ---
    if (hit) {
        meta[set][way].rrpv = 0;
        meta[set][way].dead_ctr = 3;
        // Update SHiP table: increment reuse counter (max 3)
        if (ship_table[meta[set][way].sig].reuse_ctr < 3)
            ship_table[meta[set][way].sig].reuse_ctr++;
        return;
    }

    // --- On miss/fill: choose insertion depth ---
    uint8_t ins_rrpv = 3; // Default: distant
    if (is_stream) {
        // Streaming: bypass (do not insert) if possible, else insert at distant RRPV
        ins_rrpv = 3;
    } else {
        // Use SHiP outcome counter to bias insertion
        if (ship_table[sig].reuse_ctr >= 2)
            ins_rrpv = 0; // MRU insertion for "good" PCs
        else
            ins_rrpv = 3; // Distant for "bad" PCs
    }
    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].dead_ctr = 3; // Assume live on fill
    meta[set][way].sig = sig;

    // --- On victim: update SHiP outcome counter if not reused ---
    if (!hit) {
        uint8_t victim_sig = meta[set][way].sig;
        if (ship_table[victim_sig].reuse_ctr > 0)
            ship_table[victim_sig].reuse_ctr--;
    }
    // Dead-block decay handled in heartbeat
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print SHiP table histogram and streaming sets
    uint32_t good_sig = 0, bad_sig = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_table[i].reuse_ctr >= 2) good_sig++;
        else bad_sig++;
    }
    uint32_t stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].stream_conf >= 2) stream_sets++;
    std::cout << "SHiP-SBD: good_sig=" << good_sig << ", bad_sig=" << bad_sig
              << ", streaming sets=" << stream_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age dead-counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].dead_ctr > 0)
                meta[s][w].dead_ctr--;
}