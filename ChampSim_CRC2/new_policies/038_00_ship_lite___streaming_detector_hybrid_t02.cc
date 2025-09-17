#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 2048 // 2K entries
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX 3

// Streaming detector parameters
#define STREAM_CT_BITS 2
#define STREAM_CT_MAX 3
#define STREAM_DELTA_THRESHOLD 3 // If monotonic deltas for 3+ accesses, treat as streaming

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3

// Metadata
std::vector<uint8_t> block_rrpv;          // Per-block RRPV
std::vector<uint16_t> block_signature;    // Per-block SHiP signature
std::vector<uint8_t> ship_table;          // Global SHiP table: 2K entries, 2 bits each
std::vector<uint64_t> set_last_addr;      // Per-set: last address seen
std::vector<uint8_t> set_stream_ct;       // Per-set: streaming counter

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t ship_mru_inserts = 0;
uint64_t stream_bypass = 0;

// Helper: get SHiP signature from PC
inline uint16_t get_signature(uint64_t PC) {
    // Use lower SHIP_SIG_BITS of CRC32(PC)
    return champsim_crc32(PC) & SHIP_SIG_MASK;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_signature.resize(LLC_SETS * LLC_WAYS, 0);
    ship_table.resize(SHIP_SIG_ENTRIES, SHIP_COUNTER_MAX / 2); // Start at weak reuse
    set_last_addr.resize(LLC_SETS, 0);
    set_stream_ct.resize(LLC_SETS, 0);
    access_counter = 0;
    hits = 0;
    ship_mru_inserts = 0;
    stream_bypass = 0;
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
    // Streaming bypass: if set streaming counter is saturated, prefer RRPV=3 blocks
    if (set_stream_ct[set] >= STREAM_CT_MAX) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            size_t idx = set * LLC_WAYS + way;
            if (block_rrpv[idx] == RRPV_MAX)
                return way;
        }
    }
    // RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] < RRPV_MAX)
            block_rrpv[idx]++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Fallback
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
    access_counter++;

    size_t idx = set * LLC_WAYS + way;
    uint16_t sig = get_signature(PC);

    // --- Streaming detector update ---
    uint64_t last_addr = set_last_addr[set];
    uint64_t delta = (last_addr > 0) ? (paddr > last_addr ? paddr - last_addr : last_addr - paddr) : 0;
    // If delta is small and monotonic (e.g., stride-1 or stride-N), increment streaming counter
    if (last_addr > 0 && (delta == 64 || delta == 128 || delta == 256)) {
        if (set_stream_ct[set] < STREAM_CT_MAX)
            set_stream_ct[set]++;
    } else {
        if (set_stream_ct[set] > 0)
            set_stream_ct[set]--;
    }
    set_last_addr[set] = paddr;

    // --- SHiP table update ---
    // On hit: promote to MRU, increment SHiP counter
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        block_signature[idx] = sig;
        if (ship_table[sig] < SHIP_COUNTER_MAX)
            ship_table[sig]++;
        return;
    }

    // On miss: update SHiP counter for victim block's signature
    uint16_t victim_sig = block_signature[idx];
    if (victim_sig < SHIP_SIG_ENTRIES) {
        if (ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
    }

    // --- Streaming bypass logic ---
    if (set_stream_ct[set] >= STREAM_CT_MAX) {
        // Streaming detected: insert at RRPV=3 (LRU), or bypass (simulate by not resetting RRPV)
        block_rrpv[idx] = RRPV_MAX;
        stream_bypass++;
        block_signature[idx] = sig;
        return;
    }

    // --- SHiP insertion policy ---
    // If SHiP counter for this signature is strong (>=2), insert at MRU (RRPV=0)
    if (ship_table[sig] >= 2) {
        block_rrpv[idx] = 0;
        ship_mru_inserts++;
    } else {
        block_rrpv[idx] = RRPV_MAX;
    }
    block_signature[idx] = sig;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Detector Hybrid Policy\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "SHiP MRU inserts: " << ship_mru_inserts << "\n";
    std::cout << "Streaming bypass events: " << stream_bypass << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP+Stream heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", ship_mru_inserts=" << ship_mru_inserts
              << ", stream_bypass=" << stream_bypass << "\n";
}