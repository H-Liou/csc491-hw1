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
#define RRPV_INSERT_SRRIP 2   // SRRIP: insert at RRPV=2
#define RRPV_INSERT_BRRIP 3   // BRRIP: insert at RRPV=3 (MRU only every 1/32 fills)
#define RRPV_INSERT_MRU 0

// SHiP-lite signature table
#define SIG_BITS 5
#define SIG_ENTRIES (1 << SIG_BITS)      // 32 entries
#define SIG_COUNTER_BITS 2
#define SIG_COUNTER_MAX ((1 << SIG_COUNTER_BITS) - 1)
#define SIG_REUSE_THRESHOLD 1

// DRRIP/DIP set dueling
#define LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3

struct BLOCK_META {
    uint8_t rrpv;                 // 2 bits
    uint8_t signature;            // 5 bits
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<BLOCK_META> block_meta;
std::vector<STREAM_DETECTOR> stream_detector;

// SHiP-lite signature table: 32 entries × 2 bits
std::vector<uint8_t> sig_table;

// DRRIP global policy selector
uint16_t psel = PSEL_INIT;

// Leader sets: first 32 for SRRIP, next 32 for BRRIP
std::vector<uint8_t> is_srrip_leader;
std::vector<uint8_t> is_brrip_leader;

// Statistics
uint64_t access_counter = 0;
uint64_t streaming_bypass = 0;
uint64_t ship_hits = 0;
uint64_t ship_promotes = 0;
uint64_t dr_insert_srrip = 0;
uint64_t dr_insert_brrip = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// SHiP-lite: extract 5-bit signature from PC
inline uint8_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 7)) & (SIG_ENTRIES - 1);
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
    is_srrip_leader.resize(LLC_SETS, 0);
    is_brrip_leader.resize(LLC_SETS, 0);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = RRPV_MAX;
        block_meta[i].signature = 0;
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
    // Assign leader sets (first 32 for SRRIP, last 32 for BRRIP)
    for (uint32_t i = 0; i < LEADER_SETS; i++) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS - 1 - i] = 1;
    }
    access_counter = 0;
    streaming_bypass = 0;
    ship_hits = 0;
    ship_promotes = 0;
    dr_insert_srrip = 0;
    dr_insert_brrip = 0;
    psel = PSEL_INIT;
}

// Victim selection: SRRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV_MAX
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

    // Streaming detection (per set)
    update_streaming_detector(set, paddr);

    // On streaming: bypass fill (do not insert into cache)
    if (stream_detector[set].streaming) {
        meta.rrpv = RRPV_MAX; // mark as least likely reused
        meta.signature = get_signature(PC);
        streaming_bypass++;
        return;
    }

    uint8_t signature = get_signature(PC);

    // On cache hit
    if (hit) {
        // Promote block to MRU
        meta.rrpv = RRPV_INSERT_MRU;
        // SHiP: increment signature reuse counter (max saturate)
        if (sig_table[meta.signature] < SIG_COUNTER_MAX)
            sig_table[meta.signature]++;
        ship_hits++;
        ship_promotes++;
        return;
    }

    // On miss: insertion
    meta.signature = signature;

    // DRRIP set dueling: choose SRRIP or BRRIP
    uint8_t use_srrip = 0, use_brrip = 0;
    if (is_srrip_leader[set]) use_srrip = 1;
    if (is_brrip_leader[set]) use_brrip = 1;

    uint8_t insertion_rrpv = RRPV_INSERT_SRRIP;
    static uint32_t brrip_ctr = 0;
    if (use_brrip || (!use_srrip && !use_brrip && psel < (PSEL_MAX / 2))) {
        // BRRIP: insert at RRPV_MAX except every 1/32 fills (MRU)
        brrip_ctr++;
        if ((brrip_ctr & 0x1F) == 0)
            insertion_rrpv = RRPV_INSERT_MRU;
        else
            insertion_rrpv = RRPV_INSERT_BRRIP;
        dr_insert_brrip++;
    } else if (use_srrip || (!use_srrip && !use_brrip && psel >= (PSEL_MAX / 2))) {
        insertion_rrpv = RRPV_INSERT_SRRIP;
        dr_insert_srrip++;
    }

    // SHiP-lite: if signature shows reuse, insert at MRU else DRRIP value
    if (sig_table[signature] > SIG_REUSE_THRESHOLD) {
        insertion_rrpv = RRPV_INSERT_MRU;
        ship_promotes++;
    }

    meta.rrpv = insertion_rrpv;

    // SHiP: on eviction, decrement signature reuse counter (min 0)
    uint8_t victim_sig = get_signature(PC);
    if (!hit) {
        if (sig_table[victim_sig] > 0)
            sig_table[victim_sig]--;
    }

    // Update PSEL for leader sets
    if (use_srrip) {
        if (hit && psel < PSEL_MAX) psel++;
    }
    if (use_brrip) {
        if (hit && psel > 0) psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHIP-Stream: SHiP-lite DRRIP Streaming Bypass stats\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming bypasses: " << streaming_bypass << "\n";
    std::cout << "SHiP hits: " << ship_hits << "\n";
    std::cout << "SHiP MRU promotions: " << ship_promotes << "\n";
    std::cout << "SRRIP fills: " << dr_insert_srrip << "\n";
    std::cout << "BRRIP fills: " << dr_insert_brrip << "\n";
    std::cout << "PSEL value: " << psel << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHIP-Stream heartbeat: accesses=" << access_counter
              << ", streaming_bypass=" << streaming_bypass
              << ", ship_hits=" << ship_hits
              << ", ship_promotes=" << ship_promotes
              << ", psel=" << psel << "\n";
}