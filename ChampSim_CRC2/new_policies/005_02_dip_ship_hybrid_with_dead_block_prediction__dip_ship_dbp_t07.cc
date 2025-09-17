#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP constants
#define LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)

// SHiP-lite signature
#define SIG_BITS 6
#define SIG_ENTRIES (1 << SIG_BITS)      // 64 entries
#define SIG_COUNTER_BITS 2
#define SIG_COUNTER_MAX ((1 << SIG_COUNTER_BITS) - 1)
#define SIG_REUSE_THRESHOLD 1

// Dead-block predictor
#define DEAD_DECAY_PERIOD 8192

// Streaming detection
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3

struct BLOCK_META {
    uint8_t rrpv : 2;         // 2 bits
    uint8_t signature : 6;    // 6 bits
    uint8_t dead : 1;         // 1 bit
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<BLOCK_META> block_meta;
std::vector<uint8_t> sig_table;      // 64 entries × 2 bits
std::vector<STREAM_DETECTOR> stream_detector;

uint16_t psel = PSEL_INIT;
std::vector<uint8_t> is_lip_leader;
std::vector<uint8_t> is_bip_leader;

uint64_t access_counter = 0;
uint64_t dead_evictions = 0;
uint64_t streaming_sets = 0;
uint64_t lip_fills = 0;
uint64_t bip_fills = 0;
uint64_t ship_mru_fills = 0;
uint64_t ship_hits = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// SHiP-lite: extract 6-bit signature from PC
inline uint8_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 13)) & (SIG_ENTRIES - 1);
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

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    sig_table.resize(SIG_ENTRIES, SIG_COUNTER_MAX / 2);
    stream_detector.resize(LLC_SETS);
    is_lip_leader.resize(LLC_SETS, 0);
    is_bip_leader.resize(LLC_SETS, 0);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3;
        block_meta[i].signature = 0;
        block_meta[i].dead = 0;
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
    // Assign leader sets (first 32 for LIP, last 32 for BIP)
    for (uint32_t i = 0; i < LEADER_SETS / 2; i++) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS - 1 - i] = 1;
    }
    access_counter = 0;
    dead_evictions = 0;
    streaming_sets = 0;
    lip_fills = 0;
    bip_fills = 0;
    ship_mru_fills = 0;
    ship_hits = 0;
    psel = PSEL_INIT;
}

// Victim selection: prefer dead blocks, then blocks with RRPV==3
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].dead)
            return way;
    }
    // Else, prefer blocks with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
            return way;
    }
    // Else, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv < 3)
            block_meta[idx].rrpv++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
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

    // Dead-block predictor periodic decay
    if ((access_counter & (DEAD_DECAY_PERIOD - 1)) == 0) {
        for (size_t i = 0; i < block_meta.size(); i++) {
            block_meta[i].dead = 0; // Clear dead bits every period
        }
    }

    size_t idx = get_block_meta_idx(set, way);
    BLOCK_META &meta = block_meta[idx];

    // Update streaming detector
    update_streaming_detector(set, paddr);

    uint8_t signature = get_signature(PC);

    // On cache hit
    if (hit) {
        // Promote to MRU (RRPV=0)
        meta.rrpv = 0;
        meta.dead = 0;
        // SHiP: increment signature reuse counter (max saturate)
        if (sig_table[meta.signature] < SIG_COUNTER_MAX)
            sig_table[meta.signature]++;
        ship_hits++;
        return;
    }

    // On miss: insertion policy selection
    meta.signature = signature;

    // DIP logic: select LIP or BIP insertion
    uint8_t use_lip = 0, use_bip = 0;
    if (is_lip_leader[set]) use_lip = 1;
    if (is_bip_leader[set]) use_bip = 1;

    uint8_t insertion_rrpv = 3; // LIP: always LRU
    static uint32_t bip_ctr = 0;
    if (use_bip || (!use_lip && !use_bip && psel < (PSEL_MAX / 2))) {
        bip_ctr++;
        if ((bip_ctr & 0x1F) == 0)
            insertion_rrpv = 0; // MRU every 1/32
        else
            insertion_rrpv = 3;
        bip_fills++;
    } else if (use_lip || (!use_lip && !use_bip && psel >= (PSEL_MAX / 2))) {
        insertion_rrpv = 3;
        lip_fills++;
    }

    // SHiP-lite: if signature shows reuse, insert at MRU
    if (sig_table[signature] > SIG_REUSE_THRESHOLD) {
        insertion_rrpv = 0;
        ship_mru_fills++;
    }

    // Streaming detection or dead-block: if streaming or signature shows no reuse, insert at max RRPV and mark as dead
    if (stream_detector[set].streaming || sig_table[signature] == 0) {
        insertion_rrpv = 3;
        meta.dead = 1;
        streaming_sets++;
    } else {
        meta.dead = 0;
    }
    meta.rrpv = insertion_rrpv;

    // On eviction, decrement signature reuse counter (min 0)
    uint8_t victim_sig = get_signature(PC);
    if (!hit) {
        if (sig_table[victim_sig] > 0)
            sig_table[victim_sig]--;
    }

    // Update PSEL for leader sets
    if (use_lip) {
        if (hit && psel < PSEL_MAX) psel++;
    }
    if (use_bip) {
        if (hit && psel > 0) psel--;
    }

    // Track dead-block evictions
    if (meta.dead)
        dead_evictions++;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DIP-SHiP-DBP Hybrid stats\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Dead-block evictions: " << dead_evictions << "\n";
    std::cout << "Streaming sets: " << streaming_sets << "\n";
    std::cout << "LIP fills: " << lip_fills << "\n";
    std::cout << "BIP fills: " << bip_fills << "\n";
    std::cout << "SHiP MRU fills: " << ship_mru_fills << "\n";
    std::cout << "SHiP hits: " << ship_hits << "\n";
    std::cout << "PSEL value: " << psel << "\n";
    size_t streaming_set_count = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_set_count++;
    }
    std::cout << "Streaming sets detected: " << streaming_set_count << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DIP-SHiP-DBP heartbeat: accesses=" << access_counter
              << ", dead_evictions=" << dead_evictions
              << ", streaming_sets=" << streaming_sets
              << ", lip_fills=" << lip_fills
              << ", bip_fills=" << bip_fills
              << ", ship_hits=" << ship_hits
              << ", psel=" << psel << "\n";
}