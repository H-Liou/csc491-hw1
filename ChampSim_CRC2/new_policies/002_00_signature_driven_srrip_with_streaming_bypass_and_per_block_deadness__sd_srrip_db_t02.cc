#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define RRPV_MRU 0
#define RRPV_DISTANT 2
#define RRPV_LRU RRPV_MAX

// SHiP-lite constants
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1 << SHIP_COUNTER_BITS) - 1)

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3 // 3/4 monotonic deltas triggers streaming

struct BLOCK_META {
    uint8_t rrpv;       // 2 bits
    uint8_t ship_sig;   // 6 bits
    uint8_t dead;       // 1 bit
};

struct SHIP_SIG_ENTRY {
    uint8_t reuse_counter; // 2 bits
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
};

std::vector<BLOCK_META> block_meta;
std::vector<SHIP_SIG_ENTRY> ship_sig_table;
std::vector<STREAM_DETECTOR> stream_detector;

uint64_t access_counter = 0;
uint64_t streaming_bypass_fills = 0;
uint64_t dead_blocks_evicted = 0;

// Helper: get SHiP signature from PC
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 3)) & (SHIP_SIG_ENTRIES - 1);
}

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: streaming detection
bool is_streaming_set(uint32_t set, uint64_t curr_addr) {
    STREAM_DETECTOR &sd = stream_detector[set];
    int64_t delta = curr_addr - sd.last_addr;
    if (sd.last_addr != 0) {
        sd.delta_history[sd.ptr] = delta;
        sd.ptr = (sd.ptr + 1) % STREAM_DELTA_HISTORY;
    }
    sd.last_addr = curr_addr;
    // Check if most recent deltas are monotonic (all same sign and nonzero)
    int positive = 0, negative = 0, nonzero = 0;
    for (int i = 0; i < STREAM_DELTA_HISTORY; i++) {
        if (sd.delta_history[i] > 0) positive++;
        else if (sd.delta_history[i] < 0) negative++;
        if (sd.delta_history[i] != 0) nonzero++;
    }
    if (nonzero >= STREAM_DELTA_THRESHOLD &&
        (positive >= STREAM_DELTA_THRESHOLD || negative >= STREAM_DELTA_THRESHOLD)) {
        return true;
    }
    return false;
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    ship_sig_table.resize(SHIP_SIG_ENTRIES);
    stream_detector.resize(LLC_SETS);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = RRPV_LRU;
        block_meta[i].ship_sig = 0;
        block_meta[i].dead = 1;
    }
    for (size_t i = 0; i < ship_sig_table.size(); i++) {
        ship_sig_table[i].reuse_counter = 1; // Start neutral
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
    }
}

// Victim selection: RRIP with dead-block preference
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks for eviction
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].dead == 1)
            return way;
    }
    // Otherwise, RRIP: find block with RRPV_MAX
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX)
            return way;
    }
    // If none, increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv < RRPV_MAX)
            block_meta[idx].rrpv++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX)
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

    size_t idx = get_block_meta_idx(set, way);
    BLOCK_META &meta = block_meta[idx];

    // Streaming detection: if streaming, bypass fill (insert at RRPV=3, dead=1)
    bool streaming = is_streaming_set(set, paddr);

    // SHiP signature
    uint8_t sig = get_ship_sig(PC);

    if (hit) {
        // On hit: promote to MRU, clear deadness, increment SHiP counter
        meta.rrpv = RRPV_MRU;
        meta.dead = 0;
        if (ship_sig_table[sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[sig].reuse_counter++;
        return;
    }

    // On fill (miss)
    meta.ship_sig = sig;
    meta.dead = 1; // Mark as dead until proven reused

    if (streaming) {
        // Streaming: bypass by inserting at RRPV=3, dead=1
        meta.rrpv = RRPV_LRU;
        streaming_bypass_fills++;
    } else if (ship_sig_table[sig].reuse_counter >= (SHIP_COUNTER_MAX - 1)) {
        // Strong reuse: insert at MRU, dead=0
        meta.rrpv = RRPV_MRU;
        meta.dead = 0;
    } else {
        // Otherwise: insert at distant RRPV, dead=1
        meta.rrpv = RRPV_DISTANT;
    }

    // On eviction: update SHiP counter based on deadness
    uint32_t victim_way = GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
    size_t victim_idx = get_block_meta_idx(set, victim_way);
    BLOCK_META &victim_meta = block_meta[victim_idx];
    uint8_t victim_sig = victim_meta.ship_sig;
    if (victim_meta.dead == 1) {
        // Dead block evicted: decrement SHiP counter
        if (ship_sig_table[victim_sig].reuse_counter > 0)
            ship_sig_table[victim_sig].reuse_counter--;
        dead_blocks_evicted++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SD-SRRIP-DB: Signature-Driven SRRIP + Streaming Bypass + Deadness stats\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming fills bypassed: " << streaming_bypass_fills << "\n";
    std::cout << "Dead blocks evicted: " << dead_blocks_evicted << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (is_streaming_set(i, stream_detector[i].last_addr)) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SD-SRRIP-DB heartbeat: accesses=" << access_counter
              << ", streaming_bypass_fills=" << streaming_bypass_fills
              << ", dead_blocks_evicted=" << dead_blocks_evicted << "\n";
}