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
#define RRPV_INSERT_MRU 0
#define RRPV_INSERT_DISTANT 3

// SHiP-lite signature
#define SIG_BITS 6
#define SIG_MASK ((1 << SIG_BITS) - 1)
#define OUTCOME_BITS 2
#define OUTCOME_MAX ((1 << OUTCOME_BITS) - 1)
#define OUTCOME_TABLE_SIZE 2048 // 2K-entry global table

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3

// DIP set-dueling
#define LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)

struct BLOCK_META {
    uint8_t rrpv;           // 2 bits
    uint8_t sig;            // 6 bits
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<BLOCK_META> block_meta;
std::vector<STREAM_DETECTOR> stream_detector;

// SHiP-lite global outcome table (indexed by PC signature)
std::vector<uint8_t> outcome_table; // 2 bits per entry

// DIP set-dueling
std::vector<uint8_t> is_ship_leader;
std::vector<uint8_t> is_bip_leader;
uint16_t psel = PSEL_INIT;

// Stats
uint64_t access_counter = 0;
uint64_t streaming_bypass = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Get SHiP signature from PC
inline uint8_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 7)) & SIG_MASK;
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
    stream_detector.resize(LLC_SETS);
    outcome_table.resize(OUTCOME_TABLE_SIZE, OUTCOME_MAX / 2);
    is_ship_leader.resize(LLC_SETS, 0);
    is_bip_leader.resize(LLC_SETS, 0);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = RRPV_MAX;
        block_meta[i].sig = 0;
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
    // Assign leader sets: first 32 for SHiP, last 32 for BIP
    for (uint32_t i = 0; i < LEADER_SETS / 2; i++) {
        is_ship_leader[i] = 1;
        is_bip_leader[LLC_SETS - 1 - i] = 1;
    }
    psel = PSEL_INIT;
    access_counter = 0;
    streaming_bypass = 0;
}

// Victim selection: RRIP
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

    // Streaming detection
    update_streaming_detector(set, paddr);

    // Streaming phase: bypass cache fill
    if (stream_detector[set].streaming) {
        meta.rrpv = RRPV_MAX;
        meta.sig = 0;
        streaming_bypass++;
        return;
    }

    uint8_t sig = get_signature(PC);
    meta.sig = sig;

    // On cache hit: update outcome table and promote to MRU
    if (hit) {
        meta.rrpv = RRPV_INSERT_MRU;
        // Outcome table: increment counter (max OUTCOME_MAX)
        if (outcome_table[sig] < OUTCOME_MAX) outcome_table[sig]++;
        // Update PSEL for leader sets
        if (is_ship_leader[set] && psel < PSEL_MAX) psel++;
        if (is_bip_leader[set] && psel > 0) psel--;
        return;
    }

    // DIP: select insertion policy
    bool use_ship = is_ship_leader[set] || (!is_ship_leader[set] && !is_bip_leader[set] && psel >= (PSEL_MAX / 2));
    bool use_bip  = is_bip_leader[set]  || (!is_ship_leader[set] && !is_bip_leader[set] && psel < (PSEL_MAX / 2));

    uint8_t insertion_rrpv = RRPV_INSERT_DISTANT;
    static uint32_t bip_ctr = 0;

    if (use_bip) {
        bip_ctr++;
        if ((bip_ctr & 0x1F) == 0)
            insertion_rrpv = RRPV_INSERT_MRU;
        else
            insertion_rrpv = RRPV_INSERT_DISTANT;
    } else if (use_ship) {
        // SHiP: if outcome table shows reuse, insert MRU; else distant
        if (outcome_table[sig] >= (OUTCOME_MAX / 2))
            insertion_rrpv = RRPV_INSERT_MRU;
        else
            insertion_rrpv = RRPV_INSERT_DISTANT;
    }

    meta.rrpv = insertion_rrpv;

    // On block eviction: decrement outcome table for signature
    if (!hit && victim_addr != 0) {
        uint8_t victim_sig = get_signature(PC); // Use victim's PC if available, else current
        if (outcome_table[victim_sig] > 0) outcome_table[victim_sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-SB-DIP: SHiP-lite + Streaming Bypass + DIP stats\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming bypasses: " << streaming_bypass << "\n";
    std::cout << "PSEL value: " << psel << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP-SB-DIP heartbeat: accesses=" << access_counter
              << ", streaming_bypass=" << streaming_bypass
              << ", psel=" << psel << "\n";
}