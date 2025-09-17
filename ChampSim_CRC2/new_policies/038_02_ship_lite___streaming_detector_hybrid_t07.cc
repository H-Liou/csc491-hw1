#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite parameters
#define SHIP_SIG_BITS 6        // PC signature bits per set
#define SHIP_ENTRIES 64        // signatures per set (2^6)
#define OUTCOME_BITS 2         // each entry: 2-bit saturating counter

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3
#define SHIP_FRIENDLY_RRPV 0   // Insert at MRU if predictor says reuse
#define SHIP_DISTANT_RRPV 3    // Insert at LRU if predictor says no reuse

// Streaming detector parameters
#define STREAM_WIN_SIZE 4      // # recent deltas tracked per set
#define STREAM_STRIDE_TOL 2    // Allow up to 2 different strides to count as streaming

// Metadata
std::vector<uint8_t> block_rrpv;                 // Per-block RRPV
std::vector<uint16_t> block_signature;           // Per-block: SHiP signature
struct SHIPEntry {
    uint8_t counter; // 2 bits
    uint16_t signature; // 6 bits
};
std::vector<std::vector<SHIPEntry>> ship_table;  // Per-set SHiP-lite table [set][entry]

// Streaming detector: per-set window of last N address deltas
std::vector<std::vector<int64_t>> stream_deltas; // [set][STREAM_WIN_SIZE]
std::vector<uint64_t> stream_last_addr;          // [set]
std::vector<uint8_t> stream_is_streaming;        // [set]

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t ship_bypass = 0;
uint64_t streaming_bypass = 0;

// --- Helper functions ---

// Get SHiP signature: lower SHIP_SIG_BITS of PC
inline uint16_t get_signature(uint64_t PC) {
    return (PC >> 2) & ((1 << SHIP_SIG_BITS) - 1);
}

// Find index of signature in SHiP table
inline uint32_t ship_index(uint16_t sig) {
    return sig & (SHIP_ENTRIES - 1);
}

// Streaming detection: returns true if last N deltas are similar
bool detect_streaming(uint32_t set, uint64_t paddr) {
    int64_t delta = stream_last_addr[set] ? (int64_t)paddr - (int64_t)stream_last_addr[set] : 0;
    stream_last_addr[set] = paddr;

    // Insert delta into window
    auto& win = stream_deltas[set];
    win.insert(win.begin(), delta);
    if (win.size() > STREAM_WIN_SIZE)
        win.pop_back();
    // Count unique deltas (ignore zero)
    std::vector<int64_t> unique;
    for (auto d : win) {
        if (d == 0) continue;
        bool found = false;
        for (auto u : unique) if (u == d) found = true;
        if (!found) unique.push_back(d);
    }
    stream_is_streaming[set] = (unique.size() <= STREAM_STRIDE_TOL) && (win.size() == STREAM_WIN_SIZE);
    return stream_is_streaming[set];
}

// --- Core functions ---

void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_signature.resize(LLC_SETS * LLC_WAYS, 0);

    ship_table.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; set++) {
        ship_table[set].resize(SHIP_ENTRIES);
        for (uint32_t i = 0; i < SHIP_ENTRIES; i++)
            ship_table[set][i] = {1, (uint16_t)i}; // Default: weak reuse
    }

    stream_deltas.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; set++)
        stream_deltas[set] = std::vector<int64_t>();
    stream_last_addr.resize(LLC_SETS, 0);
    stream_is_streaming.resize(LLC_SETS, 0);

    access_counter = 0;
    hits = 0;
    ship_bypass = 0;
    streaming_bypass = 0;
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
    // Streaming detector: prefer victim with max RRPV if streaming
    if (stream_is_streaming[set]) {
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

    // Streaming detection
    bool streaming = detect_streaming(set, paddr);

    size_t idx = set * LLC_WAYS + way;
    uint16_t sig = get_signature(PC);
    uint32_t ship_i = ship_index(sig);

    // On hit: promote to MRU, update SHiP table (positive outcome)
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        block_signature[idx] = sig;
        if (ship_table[set][ship_i].counter < 3)
            ship_table[set][ship_i].counter++;
        return;
    }

    // Streaming bypass: if streaming detected, insert at RRPV_MAX, do not update SHiP
    if (streaming) {
        block_rrpv[idx] = RRPV_MAX;
        streaming_bypass++;
        // Optionally: don't update SHiP on streaming
        block_signature[idx] = sig;
        return;
    }

    // SHiP-lite insertion: use outcome counter to bias insertion
    uint8_t ship_pred = ship_table[set][ship_i].counter;
    if (ship_pred >= 2) {
        block_rrpv[idx] = SHIP_FRIENDLY_RRPV; // likely reuse
    } else {
        block_rrpv[idx] = SHIP_DISTANT_RRPV; // likely dead
        ship_bypass++;
    }
    block_signature[idx] = sig;

    // On miss: negative outcome for previous block's signature
    uint16_t victim_sig = block_signature[idx];
    uint32_t victim_i = ship_index(victim_sig);
    if (ship_table[set][victim_i].counter > 0)
        ship_table[set][victim_i].counter--;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Detector Hybrid Policy\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "SHiP bypass events: " << ship_bypass << "\n";
    std::cout << "Streaming bypass events: " << streaming_bypass << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP+Streaming heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", SHIP_bypass=" << ship_bypass
              << ", streaming_bypass=" << streaming_bypass << "\n";
}