#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite parameters
#define SIG_BITS 6
#define SIG_ENTRIES 4096 // 4K entries, 6-bit index
#define SIG_MASK (SIG_ENTRIES - 1)
#define SIG_CTR_BITS 2
#define SIG_CTR_MAX 3

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3

// Streaming detector parameters
#define STREAM_WIN 8
#define STREAM_THRESH 6

// Per-block metadata
std::vector<uint8_t> block_rrpv; // 2 bits per block
std::vector<uint16_t> block_sig; // 6 bits per block

// SHiP-lite signature table: 2-bit outcome counter per signature
std::vector<uint8_t> sig_table; // 4096 x 2 bits

// Streaming detector: per-set recent address deltas
std::vector<uint64_t> set_last_addr; // last address per set
std::vector<uint8_t> set_stream_cnt; // streaming counter per set

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t bypasses = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: get SHiP signature
inline uint16_t get_signature(uint64_t PC) {
    return champsim_crc2(PC) & SIG_MASK;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_sig.resize(LLC_SETS * LLC_WAYS, 0);
    sig_table.resize(SIG_ENTRIES, 1); // neutral: weak reuse
    set_last_addr.resize(LLC_SETS, 0);
    set_stream_cnt.resize(LLC_SETS, 0);

    access_counter = 0;
    hits = 0;
    bypasses = 0;
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
    // Streaming detector: if streaming, bypass (return special value)
    if (set_stream_cnt[set] >= STREAM_THRESH)
        return LLC_WAYS; // signal bypass

    // Standard RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] < RRPV_MAX)
            block_rrpv[idx]++;
    }
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
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

    // Streaming detector: update per-set delta history
    uint64_t last_addr = set_last_addr[set];
    uint64_t delta = (last_addr) ? std::abs((int64_t)paddr - (int64_t)last_addr) : 0;
    if (last_addr && delta && delta < 1024) { // small stride
        if (set_stream_cnt[set] < STREAM_WIN)
            set_stream_cnt[set]++;
    } else {
        if (set_stream_cnt[set] > 0)
            set_stream_cnt[set]--;
    }
    set_last_addr[set] = paddr;

    // If bypassed, do nothing
    if (way == LLC_WAYS) {
        bypasses++;
        return;
    }

    size_t idx = get_block_idx(set, way);
    uint16_t sig = get_signature(PC);

    // On hit: promote to MRU, update SHiP outcome
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        block_sig[idx] = sig;
        // Strengthen outcome
        if (sig_table[sig] < SIG_CTR_MAX)
            sig_table[sig]++;
        return;
    }

    // On fill: choose insertion depth based on SHiP outcome and streaming
    uint8_t ins_rrpv = RRPV_MAX; // default: LRU
    if (set_stream_cnt[set] >= STREAM_THRESH) {
        // Streaming: insert at distant RRPV or bypass (already handled in victim selection)
        ins_rrpv = RRPV_MAX;
    } else {
        // SHiP: if outcome counter is strong, insert at RRPV=0; else at RRPV=2
        if (sig_table[sig] >= SIG_CTR_MAX)
            ins_rrpv = 0;
        else if (sig_table[sig] >= 2)
            ins_rrpv = 1;
        else
            ins_rrpv = 2;
    }
    block_rrpv[idx] = ins_rrpv;
    block_sig[idx] = sig;

    // On eviction: update SHiP outcome for victim block
    if (victim_addr != 0) {
        uint16_t victim_sig = block_sig[idx];
        // If block was not reused (RRPV==RRPV_MAX), weaken outcome
        if (block_rrpv[idx] == RRPV_MAX && sig_table[victim_sig] > 0)
            sig_table[victim_sig]--;
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
    std::cout << "SHiP+Stream heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", bypasses=" << bypasses << "\n";
}