#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];    // 2-bit RRIP per block

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome per signature ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 2048
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // [0,63]
uint8_t sig_ctr[SIG_TABLE_SIZE];       // 2-bit saturating counter per signature

// --- Dead-block predictor: 2-bit per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2-bit per block

// --- Streaming detector: per-set, tracks monotonic deltas ---
uint64_t last_addr[LLC_SETS];
int8_t stride_count[LLC_SETS];         // counts consecutive monotonic strides
bool streaming_bypass[LLC_SETS];       // active streaming bypass window
uint64_t stream_window_end[LLC_SETS];  // timestamp when bypass window ends
#define STREAM_STRIDE_THRESH 3
#define STREAM_BYPASS_WINDOW 512 // accesses

// --- For periodic decay (SHIP outcome counters, dead counters) ---
uint64_t access_counter = 0;
#define DECAY_PERIOD (SIG_TABLE_SIZE * 8)

// --- Helper: initialize replacement state ---
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            dead_ctr[set][way] = 0;
        }
        last_addr[set] = 0;
        stride_count[set] = 0;
        streaming_bypass[set] = false;
        stream_window_end[set] = 0;
    }
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_ctr[i] = 1; // neutral
    access_counter = 0;
}

// --- RRIP victim selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with dead_ctr==3 (dead-block approximation)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 || dead_ctr[set][way] == 3)
            return way;
    // Standard RRIP fallback
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
    }
}

// --- Update replacement state ---
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

    // --- Streaming detector update ---
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    if (delta == 64 || delta == -64) {
        stride_count[set]++;
        if (stride_count[set] >= STREAM_STRIDE_THRESH && !streaming_bypass[set]) {
            streaming_bypass[set] = true;
            stream_window_end[set] = access_counter + STREAM_BYPASS_WINDOW;
        }
    } else if (delta != 0) {
        stride_count[set] = 0;
    }
    last_addr[set] = paddr;
    if (streaming_bypass[set] && access_counter >= stream_window_end[set])
        streaming_bypass[set] = false;

    // --- SHiP signature extraction ---
    uint32_t sig = (PC ^ (paddr>>6)) & ((1<<SIG_BITS)-1);

    // --- Update SHiP outcome counters ---
    if (hit) {
        rrpv[set][way] = 0; // MRU on hit
        if (sig_ctr[sig] < 3)
            sig_ctr[sig]++;
        if (dead_ctr[set][way] > 0)
            dead_ctr[set][way]--; // block reused, less likely dead
    } else {
        // On eviction, decrement signature counter (min 0)
        uint32_t victim_sig = block_sig[set][way];
        if (sig_ctr[victim_sig] > 0)
            sig_ctr[victim_sig]--;
        // Dead-block: increment dead counter (max 3)
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // --- Periodic decay of signature counters and dead counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
            if (sig_ctr[i] > 0)
                sig_ctr[i]--;
        for (uint32_t set2 = 0; set2 < LLC_SETS; ++set2)
            for (uint32_t way2 = 0; way2 < LLC_WAYS; ++way2)
                if (dead_ctr[set2][way2] > 0)
                    dead_ctr[set2][way2]--;
    }

    // --- SHiP bias: If signature has high reuse, insert at MRU ---
    bool strong_sig = (sig_ctr[sig] >= 2);

    // --- Dead-block bias: If block predicted dead, insert at distant or bypass ---
    bool is_dead = (dead_ctr[set][way] == 3);

    // --- Streaming bypass logic: if streaming detected, bypass all new blocks ---
    bool bypass = (streaming_bypass[set] && !hit);

    // --- Insertion logic ---
    if (bypass) {
        // Streaming detected: bypass block (insert at RRPV=3)
        rrpv[set][way] = 3;
    }
    else if (is_dead) {
        // Dead-block: insert at distant (RRPV=3)
        rrpv[set][way] = 3;
    }
    else if (strong_sig) {
        // SHiP bias: reusable block, insert at MRU
        rrpv[set][way] = 0;
    }
    else {
        // Default: insert at distant (RRPV=2)
        rrpv[set][way] = 2;
    }

    // --- Update block's signature ---
    block_sig[set][way] = sig;
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int sig2 = 0, sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_ctr[i] == 2) sig2++;
        if (sig_ctr[i] == 3) sig3++;
    }
    std::cout << "SDA-Stream: sig_ctr==2: " << sig2 << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SDA-Stream: sig_ctr==3: " << sig3 << std::endl;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3)
                dead_blocks++;
    std::cout << "SDA-Stream: dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (streaming_bypass[set])
            streaming_sets++;
    std::cout << "SDA-Stream: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_ctr[i] == 3) sig3++;
    std::cout << "SDA-Stream: sig_ctr==3: " << sig3 << std::endl;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3)
                dead_blocks++;
    std::cout << "SDA-Stream: dead blocks: " << dead_blocks << std::endl;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (streaming_bypass[set])
            streaming_sets++;
    std::cout << "SDA-Stream: Streaming sets: " << streaming_sets << std::endl;
}