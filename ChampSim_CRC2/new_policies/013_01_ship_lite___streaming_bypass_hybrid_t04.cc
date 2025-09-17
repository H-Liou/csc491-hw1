#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-Lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_MAX 3

// Streaming detector parameters
#define STREAM_WIN_SIZE 8
#define STREAM_DELTA_THRESHOLD 6

// Per-block metadata: 2-bit RRPV, 6-bit signature
std::vector<uint8_t> block_rrpv;
std::vector<uint8_t> block_sig;

// SHiP global table: 2-bit outcome counter per signature
std::vector<uint8_t> ship_table;

// Streaming detector: per-set recent address deltas
std::vector<std::vector<int64_t>> stream_delta_hist;
std::vector<uint32_t> stream_ptr;

// Statistics
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t bypasses = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: get SHiP signature from PC
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC >> 2) & (SHIP_TABLE_SIZE - 1);
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, 3); // LRU
    block_sig.resize(LLC_SETS * LLC_WAYS, 0);
    ship_table.resize(SHIP_TABLE_SIZE, 1); // neutral
    stream_delta_hist.resize(LLC_SETS, std::vector<int64_t>(STREAM_WIN_SIZE, 0));
    stream_ptr.resize(LLC_SETS, 0);

    access_counter = 0;
    hits = 0;
    bypasses = 0;
}

// Streaming detection: returns true if recent deltas are mostly monotonic
bool is_streaming(uint32_t set, uint64_t paddr) {
    uint32_t ptr = stream_ptr[set];
    int64_t last_addr = stream_delta_hist[set][(ptr + STREAM_WIN_SIZE - 1) % STREAM_WIN_SIZE];
    int64_t delta = paddr - last_addr;

    // Update history
    stream_delta_hist[set][ptr] = paddr;
    stream_ptr[set] = (ptr + 1) % STREAM_WIN_SIZE;

    // Compute deltas
    int monotonic = 0;
    for (uint32_t i = 1; i < STREAM_WIN_SIZE; ++i) {
        int64_t d = stream_delta_hist[set][i] - stream_delta_hist[set][i - 1];
        if (d == 64 || d == -64) // block size stride
            monotonic++;
    }
    return monotonic >= STREAM_DELTA_THRESHOLD;
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
    // Prefer block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == 3)
            return way;
    }
    // If none, increment all RRPVs and retry
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
    uint8_t sig = get_ship_sig(PC);

    // Streaming detection
    bool streaming = is_streaming(set, paddr);

    // On hit: promote block to MRU, update SHiP outcome
    if (hit) {
        block_rrpv[idx] = 0;
        hits++;
        if (ship_table[sig] < SHIP_COUNTER_MAX)
            ship_table[sig]++;
        return;
    }

    // On fill (miss): choose insertion depth
    if (streaming) {
        // Streaming detected: bypass or insert at distant RRPV
        block_rrpv[idx] = 3;
        bypasses++;
    } else {
        // SHiP-Lite: use outcome counter to bias insertion
        if (ship_table[sig] >= 2)
            block_rrpv[idx] = 1; // likely reused, keep longer
        else
            block_rrpv[idx] = 3; // not reused, evict soon
    }
    block_sig[idx] = sig;

    // On eviction: update SHiP outcome
    if (victim_addr != 0) {
        uint8_t victim_sig = block_sig[idx];
        // If block was reused (hit before eviction), outcome counter already incremented
        // If not, decrement outcome counter
        if (ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Bypasses/streaming fills: " << bypasses << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP+Stream heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", bypasses=" << bypasses << "\n";
}