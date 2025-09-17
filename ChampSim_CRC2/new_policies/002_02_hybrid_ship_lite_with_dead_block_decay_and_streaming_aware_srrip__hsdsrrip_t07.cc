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
#define RRPV_MID (RRPV_MAX / 2)
#define RRPV_INSERT_MRU 0
#define RRPV_INSERT_DISTANT RRPV_MAX

// SHiP-lite constants
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1 << SHIP_COUNTER_BITS) - 1)
#define SHIP_REUSE_HIGH (SHIP_COUNTER_MAX - 1)

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX ((1 << DEAD_BITS) - 1)
#define DEAD_THRESHOLD 1
#define DEAD_DECAY_PERIOD 4096

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3 // 3/4 monotonic deltas triggers streaming

struct BLOCK_META {
    uint8_t rrpv;         // 2 bits
    uint8_t dead;         // 2 bits
    uint8_t ship_sig;     // 6 bits
};

struct SHIP_SIG_ENTRY {
    uint8_t reuse_counter; // 2 bits
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<BLOCK_META> block_meta;
std::vector<SHIP_SIG_ENTRY> ship_sig_table;
std::vector<STREAM_DETECTOR> stream_detector;

uint64_t access_counter = 0;
uint64_t streaming_fills = 0;
uint64_t dead_decay_count = 0;

// Helper: get SHiP signature from PC
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 2) ^ (PC >> 7)) & (SHIP_SIG_ENTRIES - 1);
}

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Streaming detection: updates per access
void update_streaming_detector(uint32_t set, uint64_t curr_addr) {
    STREAM_DETECTOR &sd = stream_detector[set];
    int64_t delta = curr_addr - sd.last_addr;
    if (sd.last_addr != 0) {
        sd.delta_history[sd.ptr] = delta;
        sd.ptr = (sd.ptr + 1) % STREAM_DELTA_HISTORY;
    }
    sd.last_addr = curr_addr;
    // Check monotonicity
    int positive = 0, negative = 0, nonzero = 0;
    for (int i = 0; i < STREAM_DELTA_HISTORY; i++) {
        if (sd.delta_history[i] > 0) positive++;
        else if (sd.delta_history[i] < 0) negative++;
        if (sd.delta_history[i] != 0) nonzero++;
    }
    if (nonzero >= STREAM_DELTA_THRESHOLD &&
        (positive >= STREAM_DELTA_THRESHOLD || negative >= STREAM_DELTA_THRESHOLD)) {
        sd.streaming = true;
    } else {
        sd.streaming = false;
    }
}

// Dead-block decay: periodically decay all dead counters
void decay_dead_counters() {
    for (size_t i = 0; i < block_meta.size(); i++) {
        if (block_meta[i].dead > 0)
            block_meta[i].dead--;
    }
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    ship_sig_table.resize(SHIP_SIG_ENTRIES);
    stream_detector.resize(LLC_SETS);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = RRPV_MAX;
        block_meta[i].dead = DEAD_MAX / 2;
        block_meta[i].ship_sig = 0;
    }
    for (size_t i = 0; i < ship_sig_table.size(); i++) {
        ship_sig_table[i].reuse_counter = 0;
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
    access_counter = 0;
    streaming_fills = 0;
    dead_decay_count = 0;
}

// Victim selection: SRRIP, prefer dead blocks
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV_MAX and dead counter == 0
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX && block_meta[idx].dead == 0)
            return way;
    }
    // Next, any block with RRPV_MAX
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv < RRPV_MAX)
            block_meta[idx].rrpv++;
    }
    // Second pass: dead blocks
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX && block_meta[idx].dead <= DEAD_THRESHOLD)
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

    // Streaming detection (per set)
    update_streaming_detector(set, paddr);

    // Periodically decay dead counters (every DEAD_DECAY_PERIOD accesses)
    if ((access_counter & (DEAD_DECAY_PERIOD - 1)) == 0) {
        decay_dead_counters();
        dead_decay_count++;
    }

    // SHiP signature
    uint8_t sig = get_ship_sig(PC);

    // On cache hit
    if (hit) {
        // Update SHiP reuse counter
        if (ship_sig_table[sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[sig].reuse_counter++;
        // Promote block to MRU
        meta.rrpv = RRPV_INSERT_MRU;
        // Mark block as not dead
        if (meta.dead > 0) meta.dead--;
        return;
    }

    // On cache fill (miss)
    meta.ship_sig = sig;

    // Streaming phase: insert at distant RRPV
    if (stream_detector[set].streaming) {
        meta.rrpv = RRPV_INSERT_DISTANT;
        meta.dead = DEAD_MAX;
        streaming_fills++;
        return;
    }

    // SHiP predicts high reuse: insert at MRU, else MID
    if (ship_sig_table[sig].reuse_counter >= SHIP_REUSE_HIGH) {
        meta.rrpv = RRPV_INSERT_MRU;
        meta.dead = DEAD_THRESHOLD; // likely reused soon
    } else {
        // If dead counter is low, give moderate chance
        if (meta.dead <= DEAD_THRESHOLD)
            meta.rrpv = RRPV_MID;
        else
            meta.rrpv = RRPV_INSERT_DISTANT;
        meta.dead = DEAD_MAX;
    }

    // On victim eviction: update SHiP reuse counter according to block's reuse
    uint32_t victim_way = GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
    size_t victim_idx = get_block_meta_idx(set, victim_way);
    uint8_t victim_sig = block_meta[victim_idx].ship_sig;
    // If block was hit before eviction, increment reuse; else, decrement
    if (block_meta[victim_idx].dead < DEAD_MAX / 2) {
        if (ship_sig_table[victim_sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[victim_sig].reuse_counter++;
    } else {
        if (ship_sig_table[victim_sig].reuse_counter > 0)
            ship_sig_table[victim_sig].reuse_counter--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "HSDSRRIP: Hybrid SHiP-Lite Dead-Block Streaming-Aware SRRIP stats\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming fills inserted distant: " << streaming_fills << "\n";
    std::cout << "Dead-block decay rounds: " << dead_decay_count << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "HSDSRRIP heartbeat: accesses=" << access_counter
              << ", streaming_fills=" << streaming_fills
              << ", dead_decay=" << dead_decay_count << "\n";
}