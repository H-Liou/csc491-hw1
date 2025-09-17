#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite signature table parameters
#define SIGNATURE_BITS 5      // 5 bits per signature index
#define SIG_TABLE_SIZE (1<<SIGNATURE_BITS) // 32 entries
#define SIG_COUNTER_BITS 2    // 2 bits per outcome counter

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define RRPV_MRU 0            // MRU insert
#define RRPV_LRU RRPV_MAX     // LRU insert

// Streaming detector
#define STREAM_DELTA_HISTORY 4 // Track last 4 address deltas per set
#define STREAM_THRESHOLD 3     // Require 3/4 monotonic deltas to detect streaming

// Policy metadata
struct block_state_t {
    uint8_t rrpv;               // 2 bits: RRIP value
    uint8_t sig_idx;            // 5 bits: PC signature index (for SHiP-lite)
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite signature table: 32 entries (5b index), each 2b counter
std::vector<uint8_t> sig_table(SIG_TABLE_SIZE, 1); // 2b counter, initialized to weak reuse

// Streaming detector: per-set
struct stream_state_t {
    uint64_t last_addr;
    int64_t delta_hist[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool is_streaming;
};
std::vector<stream_state_t> streams(LLC_SETS);

// Leader sets for SHiP insertion tuning
#define NUM_LEADER_SETS 32
std::vector<uint8_t> leader_sets(LLC_SETS, 0); // 0: follower, 1: SHiP leader

void InitReplacementState() {
    // Blocks: RRIP LRU, sig_idx = 0
    for (uint32_t s = 0; s < LLC_SETS; s++)
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0};
    // SHiP-lite: weak reuse default
    std::fill(sig_table.begin(), sig_table.end(), 1);

    // Streaming detector: clear
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        streams[s].last_addr = 0;
        std::fill(streams[s].delta_hist, streams[s].delta_hist+STREAM_DELTA_HISTORY, 0);
        streams[s].ptr = 0;
        streams[s].is_streaming = false;
    }
    // Leader sets: assign first 32 sets as leaders
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++)
        leader_sets[i] = 1;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // RRIP victim selection
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv == RRPV_MAX)
                return w;
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv < RRPV_MAX)
                blocks[set][w].rrpv++;
    }
}

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
    // --- Streaming detector ---
    int64_t cur_delta = streams[set].last_addr ? (int64_t)paddr - (int64_t)streams[set].last_addr : 0;
    streams[set].last_addr = paddr;
    streams[set].delta_hist[streams[set].ptr] = cur_delta;
    streams[set].ptr = (streams[set].ptr + 1) % STREAM_DELTA_HISTORY;
    // Detect monotonic streaming: at least STREAM_THRESHOLD deltas same sign and similar value
    int pos=0, neg=0;
    for (int i=0; i<STREAM_DELTA_HISTORY; i++) {
        if (streams[set].delta_hist[i] > 0) pos++;
        if (streams[set].delta_hist[i] < 0) neg++;
    }
    streams[set].is_streaming = (pos >= STREAM_THRESHOLD) || (neg >= STREAM_THRESHOLD);

    // --- SHiP-lite signature ---
    uint8_t sig_idx = (PC ^ (PC>>5) ^ (PC>>12)) & (SIG_TABLE_SIZE-1); // Simple hash from PC
    blocks[set][way].sig_idx = sig_idx;

    // --- Block update ---
    if (hit) {
        // Hit: promote MRU, strengthen PC reuse
        blocks[set][way].rrpv = RRPV_MRU;
        if (sig_table[sig_idx] < 3) sig_table[sig_idx]++;
        return;
    }

    // Miss/fill
    // Streaming bypass: don't cache if set is streaming
    if (streams[set].is_streaming) {
        blocks[set][way].rrpv = RRPV_MAX;
        // Slightly weaken PC reuse
        if (sig_table[sig_idx] > 0) sig_table[sig_idx]--;
        return;
    }

    // SHiP insertion: use PC outcome counter to bias
    uint8_t ins_rrpv = (sig_table[sig_idx] >= 2) ? RRPV_MRU : RRPV_LRU;
    blocks[set][way].rrpv = ins_rrpv;
    // On fill, slightly decay PC counter if not leader set
    if (leader_sets[set]==0 && sig_table[sig_idx]>0) sig_table[sig_idx]--;

    // On eviction: if block never hit, penalize PC
    if (!hit && blocks[set][way].rrpv == RRPV_MAX && sig_table[sig_idx]>0)
        sig_table[sig_idx]--;
}

void PrintStats() {
    // Print fraction of sets streaming, and SHiP counter histogram
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++)
        if (streams[s].is_streaming) streaming_sets++;
    std::cout << "SLSB: Streaming sets=" << streaming_sets << "/" << LLC_SETS << std::endl;

    uint32_t reuse[4] = {0,0,0,0};
    for (uint32_t i=0; i<SIG_TABLE_SIZE; i++)
        reuse[sig_table[i]]++;
    std::cout << "SLSB: SHiP reuse counter histogram: ";
    for (int i=0; i<4; i++) std::cout << "[" << i << "]=" << reuse[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}