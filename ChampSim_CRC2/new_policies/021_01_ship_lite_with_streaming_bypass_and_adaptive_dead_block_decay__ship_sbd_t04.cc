#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 2048-entry signature table, 6 bits per entry (2 bits outcome, 4 bits tag)
#define SHIP_SIG_BITS 4
#define SHIP_OUT_BITS 2
#define SHIP_ENTRIES 2048
struct SHIPEntry {
    uint8_t tag;      // 4 bits
    uint8_t outcome;  // 2 bits (reuse counter)
};
SHIPEntry ship_table[SHIP_ENTRIES];

// Per-block metadata: RRPV (2 bits), dead-counter (2 bits), PC signature (4 bits)
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t dead_ctr;  // 2 bits
    uint8_t sig;       // 4 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Streaming detector: last address and delta per set (simple monotonic stream detector)
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_conf; // 2 bits, saturating
};
StreamDetect stream_meta[LLC_SETS];

// Helper: SHiP signature hash (from PC)
inline uint32_t SHIP_hash(uint64_t PC) {
    // Use lower bits of PC, xor with higher bits for more entropy
    return ((PC >> 2) ^ (PC >> 10)) & (SHIP_ENTRIES - 1);
}

// Helper: Get 4-bit signature from PC
inline uint8_t SHIP_sig(uint64_t PC) {
    return (PC ^ (PC >> 7)) & 0xF;
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

    // --- SHiP signature ---
    uint32_t sig_idx = SHIP_hash(PC);
    uint8_t sig = SHIP_sig(PC);

    // --- On hit: promote to MRU, reset dead-counter, update SHiP outcome ---
    if (hit) {
        meta[set][way].rrpv = 0;
        meta[set][way].dead_ctr = 3;
        // Update SHiP outcome if tag matches
        if (ship_table[sig_idx].tag == sig) {
            if (ship_table[sig_idx].outcome < 3) ship_table[sig_idx].outcome++;
        } else {
            ship_table[sig_idx].tag = sig;
            ship_table[sig_idx].outcome = 2;
        }
        return;
    }

    // --- On miss/fill: choose insertion depth ---
    uint8_t ins_rrpv = 3; // Default: distant
    if (is_stream) {
        // Streaming: bypass (do not insert) if possible, else insert at distant RRPV
        ins_rrpv = 3;
    } else {
        // Use SHiP outcome to bias insertion
        if (ship_table[sig_idx].tag == sig && ship_table[sig_idx].outcome >= 2)
            ins_rrpv = 0; // High reuse: insert at MRU
        else if (ship_table[sig_idx].tag == sig && ship_table[sig_idx].outcome == 1)
            ins_rrpv = 2; // Moderate reuse
        else
            ins_rrpv = 3; // Low reuse or new signature
    }
    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].dead_ctr = 3; // Assume live on fill
    meta[set][way].sig = sig;

    // --- On victim: update SHiP outcome if block was not reused ---
    if (!hit) {
        uint8_t victim_sig = meta[set][way].sig;
        uint32_t victim_idx = SHIP_hash(PC);
        if (ship_table[victim_idx].tag == victim_sig) {
            if (ship_table[victim_idx].outcome > 0) ship_table[victim_idx].outcome--;
        }
    }
    // Dead-block decay handled in heartbeat
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print SHiP table reuse histogram and streaming set count
    uint32_t stream_sets = 0;
    uint32_t high_reuse = 0, moderate_reuse = 0, low_reuse = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].stream_conf >= 2) stream_sets++;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i) {
        if (ship_table[i].outcome >= 2) high_reuse++;
        else if (ship_table[i].outcome == 1) moderate_reuse++;
        else low_reuse++;
    }
    std::cout << "SHiP-SBD: streaming sets=" << stream_sets << "/" << LLC_SETS
              << ", SHiP high/mod/low=" << high_reuse << "/" << moderate_reuse << "/" << low_reuse << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age dead-counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].dead_ctr > 0)
                meta[s][w].dead_ctr--;
}