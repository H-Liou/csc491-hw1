#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 2048 // 2K entries
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_CTR_BITS 2
#define SHIP_CTR_MAX 3

// Streaming detector parameters
#define STREAM_WINDOW 8
#define STREAM_DELTA_THRESHOLD 6 // >=6/8 monotonic deltas triggers streaming
#define STREAM_BYPASS_RRPV 3

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3

// Per-block metadata
std::vector<uint8_t> block_rrpv; // [LLC_SETS * LLC_WAYS]
std::vector<uint16_t> block_signature; // [LLC_SETS * LLC_WAYS]

// SHiP-lite signature table
std::vector<uint8_t> ship_sig_table; // [SHIP_SIG_ENTRIES], 2-bit counters

// Streaming detector per set
std::vector<uint64_t> last_addr; // [LLC_SETS]
std::vector<int32_t> stream_deltas; // [LLC_SETS * STREAM_WINDOW]
std::vector<uint8_t> stream_ptr; // [LLC_SETS]
std::vector<uint8_t> stream_score; // [LLC_SETS]

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t bypasses = 0;
uint64_t streaming_inserts = 0;
uint64_t ship_mru_inserts = 0;
uint64_t ship_lru_inserts = 0;

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_signature.resize(LLC_SETS * LLC_WAYS, 0);

    ship_sig_table.resize(SHIP_SIG_ENTRIES, SHIP_CTR_MAX / 2);

    last_addr.resize(LLC_SETS, 0);
    stream_deltas.resize(LLC_SETS * STREAM_WINDOW, 0);
    stream_ptr.resize(LLC_SETS, 0);
    stream_score.resize(LLC_SETS, 0);

    access_counter = 0;
    hits = 0;
    bypasses = 0;
    streaming_inserts = 0;
    ship_mru_inserts = 0;
    ship_lru_inserts = 0;
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
    // Streaming bypass: if streaming detected, always evict RRPV=3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] < RRPV_MAX) block_rrpv[idx]++;
    }
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

    // --- Streaming detector update ---
    uint64_t prev_addr = last_addr[set];
    int32_t delta = (prev_addr == 0) ? 0 : (int32_t)(paddr - prev_addr);
    last_addr[set] = paddr;
    size_t stream_base = set * STREAM_WINDOW;
    stream_deltas[stream_base + stream_ptr[set]] = delta;
    stream_ptr[set] = (stream_ptr[set] + 1) % STREAM_WINDOW;

    // Count monotonic deltas in window
    uint8_t monotonic = 0;
    for (uint8_t i = 1; i < STREAM_WINDOW; i++) {
        int32_t d1 = stream_deltas[stream_base + i - 1];
        int32_t d2 = stream_deltas[stream_base + i];
        if (d1 == d2 && d1 != 0) monotonic++;
    }
    stream_score[set] = monotonic;

    // --- SHiP-lite signature ---
    uint16_t sig = (PC ^ (paddr >> 6)) & SHIP_SIG_MASK;
    block_signature[idx] = sig;

    // --- On hit: promote to MRU, update SHiP outcome ---
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        // Update SHiP outcome counter
        if (ship_sig_table[sig] < SHIP_CTR_MAX) ship_sig_table[sig]++;
        return;
    }

    // --- Streaming bypass logic ---
    bool streaming = (stream_score[set] >= STREAM_DELTA_THRESHOLD);
    if (streaming) {
        // Insert at distant RRPV, minimize pollution
        block_rrpv[idx] = STREAM_BYPASS_RRPV;
        streaming_inserts++;
        bypasses++;
        // Penalize SHiP outcome for this PC
        if (ship_sig_table[sig] > 0) ship_sig_table[sig]--;
        return;
    }

    // --- SHiP-lite insertion policy ---
    if (ship_sig_table[sig] >= (SHIP_CTR_MAX / 2)) {
        // Likely reused: insert at MRU
        block_rrpv[idx] = 0;
        ship_mru_inserts++;
    } else {
        // Not reused: insert at LRU
        block_rrpv[idx] = RRPV_MAX;
        ship_lru_inserts++;
    }

    // On miss, penalize SHiP outcome for this PC
    if (ship_sig_table[sig] > 0) ship_sig_table[sig]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid Policy\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Bypasses: " << bypasses << "\n";
    std::cout << "Streaming inserts: " << streaming_inserts << "\n";
    std::cout << "SHiP MRU inserts: " << ship_mru_inserts << "\n";
    std::cout << "SHiP LRU inserts: " << ship_lru_inserts << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP+Streaming heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", bypasses=" << bypasses
              << ", streaming_inserts=" << streaming_inserts
              << ", ship_MRU=" << ship_mru_inserts
              << ", ship_LRU=" << ship_lru_inserts << "\n";
}