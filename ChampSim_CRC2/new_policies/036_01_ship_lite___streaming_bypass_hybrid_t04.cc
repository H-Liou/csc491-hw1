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
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_TABLE_SIZE 2048 // 2K entries
#define SHIP_OUTCOME_BITS 2
#define SHIP_OUTCOME_MAX 3

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3

// Streaming detector parameters
#define STREAM_HISTORY_LEN 4
#define STREAM_DELTA_THRESH 8 // Large stride threshold

// Per-block metadata
std::vector<uint8_t> block_rrpv; // 2 bits per block
std::vector<uint16_t> block_sig; // 6 bits per block

// SHiP-lite global table: outcome counters
std::vector<uint8_t> ship_table; // 2 bits per entry

// Per-set streaming detector
struct StreamHistory {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t monotonic_count;
};
std::vector<StreamHistory> stream_hist;

// Stats
uint64_t access_counter = 0;
uint6464_t hits = 0;
uint64_t bypasses = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: compute SHiP signature from PC
inline uint16_t get_ship_sig(uint64_t PC) {
    // Simple CRC or mask for compact signature
    return champsim_crc2(PC) & SHIP_SIG_MASK;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_sig.resize(LLC_SETS * LLC_WAYS, 0);
    ship_table.resize(SHIP_TABLE_SIZE, 1); // neutral initial outcome
    stream_hist.resize(LLC_SETS);
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        stream_hist[s].last_addr = 0;
        stream_hist[s].last_delta = 0;
        stream_hist[s].monotonic_count = 0;
    }
    access_counter = 0;
    hits = 0;
    bypasses = 0;
}

// Streaming detector: returns true if streaming detected
bool is_streaming(uint32_t set, uint64_t paddr) {
    StreamHistory &hist = stream_hist[set];
    int64_t delta = (hist.last_addr == 0) ? 0 : (int64_t)paddr - (int64_t)hist.last_addr;
    bool monotonic = (delta == hist.last_delta) && (delta != 0);
    if (monotonic)
        hist.monotonic_count++;
    else
        hist.monotonic_count = 0;
    hist.last_delta = delta;
    hist.last_addr = paddr;
    // Streaming if monotonic stride for 3+ accesses OR large stride
    if (hist.monotonic_count >= STREAM_HISTORY_LEN || std::abs(delta) > (STREAM_DELTA_THRESH << 6))
        return true;
    return false;
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
    // Standard RRIP: find block with RRPV==RRPV_MAX
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] < RRPV_MAX)
            block_rrpv[idx]++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Fallback: pick way 0
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

    // Streaming detection (bypass logic)
    bool stream_bypass = is_streaming(set, paddr);

    // On hit: promote to MRU, update SHiP outcome
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        uint16_t sig = block_sig[idx];
        if (ship_table[sig] < SHIP_OUTCOME_MAX)
            ship_table[sig]++;
        return;
    }

    // On fill: streaming bypass
    if (stream_bypass) {
        // Do not insert: mark block as invalid (simulate bypass)
        block_rrpv[idx] = RRPV_MAX;
        bypasses++;
        return;
    }

    // Otherwise: SHiP-lite guided insertion
    uint16_t sig = get_ship_sig(PC);
    block_sig[idx] = sig;
    uint8_t outcome = ship_table[sig];
    // If outcome counter high: insert at MRU (RRPV=0)
    // Else: insert at LRU (RRPV=RRPV_MAX)
    block_rrpv[idx] = (outcome >= 2) ? 0 : RRPV_MAX;

    // On eviction: update SHiP outcome for victim
    if (victim_addr != 0) {
        uint16_t victim_sig = block_sig[idx];
        // If block was not reused: decrement outcome
        if (!hit && ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Bypasses: " << bypasses << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP+Streaming heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", bypasses=" << bypasses << "\n";
}