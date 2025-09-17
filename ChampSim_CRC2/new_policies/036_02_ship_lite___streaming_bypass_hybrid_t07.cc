#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite parameters
#define SHIP_SIG_BITS 4                // PC signature width
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2            // 2-bit reuse outcome
#define SHIP_COUNTER_MAX 3

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3

// Streaming detector parameters
#define STREAM_DETECT_BITS 2           // 2-bit saturating stride counter
#define STREAM_DETECT_MAX 3
#define STREAM_DETECT_THRESHOLD 2      // >=2 means streaming

// Metadata
std::vector<uint8_t> block_rrpv;       // Per-block RRPV
std::vector<uint16_t> block_signature; // Per-block (4-bit) signature
std::vector<uint8_t> ship_table;       // SHiP table: 16 entries, 2 bits each
std::vector<uint8_t> set_stream;       // Per-set stride streaming detector (2 bits)
std::vector<uint64_t> set_last_addr;   // Per-set, previous address

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t bypass_counter = 0;

// Helper: hash PC to SHiP signature
inline uint8_t get_signature(uint64_t PC) {
    // CRC or bitmask for signature
    return (PC ^ (PC >> 4)) & (SHIP_TABLE_SIZE - 1);
}

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_signature.resize(LLC_SETS * LLC_WAYS, 0);
    ship_table.resize(SHIP_TABLE_SIZE, SHIP_COUNTER_MAX / 2); // neutral start
    set_stream.resize(LLC_SETS, 0);
    set_last_addr.resize(LLC_SETS, 0);

    access_counter = 0;
    hits = 0;
    bypass_counter = 0;
}

// Streaming detector: update on every access
void update_streaming(uint32_t set, uint64_t paddr) {
    uint64_t last = set_last_addr[set];
    uint64_t stride = (last == 0) ? 0 : paddr - last;
    // If stride is within cache line range and similar to previous, count up
    if (last != 0 && stride < 4096 && stride != 0) {
        if (set_stream[set] < STREAM_DETECT_MAX) set_stream[set]++;
    } else {
        if (set_stream[set] > 0) set_stream[set]--;
    }
    set_last_addr[set] = paddr;
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
    // Streaming: if set marked streaming, prefer to bypass (caller should check)
    // Otherwise, RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Increment all RRPVs and retry
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
    update_streaming(set, paddr);

    // Get block indices and signature
    size_t idx = get_block_idx(set, way);
    uint8_t sig = get_signature(PC);

    // If streaming detected, bypass (do not install)
    if (set_stream[set] >= STREAM_DETECT_THRESHOLD) {
        // Optionally, caller can skip fill. Here, mark block as invalid (RRPV=MAX)
        block_rrpv[idx] = RRPV_MAX;
        bypass_counter++;
        return;
    }

    // On hit: promote to MRU, update SHiP outcome counter
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        ship_table[sig] = std::min(ship_table[sig] + 1, SHIP_COUNTER_MAX);
        return;
    }

    // On fill: set block signature, insertion depth based on SHiP counter
    block_signature[idx] = sig;
    uint8_t reuse_pred = ship_table[sig];

    // If high reuse, insert at RRPV=0; medium reuse at RRPV=1; low reuse at RRPV=3
    if (reuse_pred == SHIP_COUNTER_MAX)
        block_rrpv[idx] = 0;
    else if (reuse_pred >= (SHIP_COUNTER_MAX / 2))
        block_rrpv[idx] = 1;
    else
        block_rrpv[idx] = RRPV_MAX;

    // On eviction: train SHiP outcome
    if (victim_addr != 0) {
        size_t victim_idx = get_block_idx(set, way);
        uint16_t victim_sig = block_signature[victim_idx];
        // If block was not reused before eviction, decrement counter
        if (block_rrpv[victim_idx] == RRPV_MAX && ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid Policy\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Bypass events: " << bypass_counter << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP+Stream heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", bypass=" << bypass_counter << "\n";
}