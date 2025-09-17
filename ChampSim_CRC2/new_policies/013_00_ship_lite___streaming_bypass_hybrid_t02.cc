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
#define SHIP_SIG_ENTRIES 4096 // 2^12
#define SHIP_SIG_MASK (SHIP_SIG_ENTRIES - 1)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX 3

// Streaming detector parameters
#define STREAM_WINDOW 4 // Number of recent deltas to track per set
#define STREAM_DELTA_THRESHOLD 3 // If >=3 out of 4 deltas are equal, treat as streaming

// Per-block metadata: RRPV, signature, outcome
std::vector<uint8_t> block_rrpv; // 2 bits per block
std::vector<uint16_t> block_sig; // 6 bits per block
std::vector<uint8_t> block_outcome; // 1 bit per block: reused (1) or not (0)

// SHiP-lite signature table: 4096 entries, 2 bits per entry
std::vector<uint8_t> ship_sig_table;

// Streaming detector: per-set, track last STREAM_WINDOW address deltas
std::vector<uint64_t> last_addr; // per set
std::vector<uint64_t> last_deltas; // per set: last delta
std::vector<uint8_t> delta_hist; // per set: 4 bits, each bit for recent delta match

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t bypasses = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: get SHiP signature from PC
inline uint16_t get_ship_sig(uint64_t PC) {
    return (PC >> 2) & SHIP_SIG_MASK;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, 3); // LRU
    block_sig.resize(LLC_SETS * LLC_WAYS, 0);
    block_outcome.resize(LLC_SETS * LLC_WAYS, 0);
    ship_sig_table.resize(SHIP_SIG_ENTRIES, 2); // neutral counter
    last_addr.resize(LLC_SETS, 0);
    last_deltas.resize(LLC_SETS, 0);
    delta_hist.resize(LLC_SETS, 0);
    access_counter = 0;
    hits = 0;
    bypasses = 0;
}

// Streaming detector: returns true if set is streaming
bool is_streaming(uint32_t set, uint64_t paddr) {
    uint64_t delta = 0;
    if (last_addr[set] != 0)
        delta = paddr - last_addr[set];
    last_addr[set] = paddr;

    // Shift delta history, insert new delta match
    uint8_t match = (delta == last_deltas[set] && delta != 0) ? 1 : 0;
    delta_hist[set] = ((delta_hist[set] << 1) | match) & 0xF; // keep 4 bits
    last_deltas[set] = delta;

    // Count number of matches in last 4
    uint8_t cnt = 0;
    for (int i = 0; i < STREAM_WINDOW; ++i)
        if (delta_hist[set] & (1 << i)) cnt++;
    return (cnt >= STREAM_DELTA_THRESHOLD);
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
    // Standard RRIP: find block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == 3)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] < 3)
            block_rrpv[idx]++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == 3)
            return way;
    }
    // If still none, pick way 0
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

    size_t idx = get_block_idx(set, way);
    uint16_t sig = get_ship_sig(PC);

    // Streaming detector: if streaming, bypass or insert at RRPV=3
    bool streaming = is_streaming(set, paddr);

    if (hit) {
        hits++;
        block_rrpv[idx] = 0; // promote to MRU
        block_outcome[idx] = 1; // mark as reused
        // Increment SHiP counter if not saturated
        if (ship_sig_table[sig] < SHIP_COUNTER_MAX)
            ship_sig_table[sig]++;
        return;
    }

    // On fill: choose insertion depth
    if (streaming) {
        // Streaming: bypass or insert at RRPV=3
        block_rrpv[idx] = 3;
        bypasses++;
    } else {
        // SHiP-lite: use signature counter
        if (ship_sig_table[sig] >= 2)
            block_rrpv[idx] = 0; // high reuse, insert MRU
        else
            block_rrpv[idx] = 3; // low reuse, insert LRU
    }
    block_sig[idx] = sig;
    block_outcome[idx] = 0; // not reused yet

    // On eviction: update SHiP counter if block was not reused
    if (victim_addr != 0) {
        size_t victim_idx = get_block_idx(set, way);
        uint16_t victim_sig = block_sig[victim_idx];
        if (block_outcome[victim_idx] == 0) {
            // Not reused: decrement SHiP counter if not zero
            if (ship_sig_table[victim_sig] > 0)
                ship_sig_table[victim_sig]--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Bypasses/streaming insertions: " << bypasses << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP+Streaming heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", bypasses=" << bypasses << "\n";
}