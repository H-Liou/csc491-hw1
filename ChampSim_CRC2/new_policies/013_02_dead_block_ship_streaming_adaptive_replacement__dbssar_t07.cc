#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 4-bit PC signature/block, global table 32 entries x 2 bits
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 4 bits/block
uint8_t pc_table[32]; // 2 bits/entry

// Dead-block predictors: 2 bits/block, periodic decay
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits/block

// Streaming detector: per-set, last addr/delta, 1-bit flag, 3-bit confidence
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_flag[LLC_SETS]; // 1 bit/set
uint8_t stream_conf[LLC_SETS];    // 3 bits/set

// RRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Helper: hash PC to 5 bits (for 32-entry table)
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 7) ^ (PC >> 13)) & 0x1F;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU on reset
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(pc_table, 1, sizeof(pc_table)); // weakly reused
    memset(dead_ctr, 0, sizeof(dead_ctr)); // neutral
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(stream_conf, 0, sizeof(stream_conf));
}

// Dead block decay interval
uint64_t global_fill_ctr = 0;
const uint64_t DEAD_DECAY_INTERVAL = 100000; // Decay every 100K fills

void DeadBlockDecay() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] > 0)
                dead_ctr[s][w]--;
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
    // Streaming: prefer bypass (do not insert, victim is invalid)
    if (streaming_flag[set]) {
        // Find invalid block first
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        // Otherwise, pick block with RRPV==3
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment RRPV until found
        while (true) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] == 3)
                    return way;
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] < 3)
                    rrpv[set][way]++;
        }
    }

    // Dead-block: prefer block with dead_ctr==0 and RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 && dead_ctr[set][way] == 0)
            return way;

    // Otherwise, pick block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;

    // Increment RRPV until found
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
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
    // --- Streaming detector update ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_conf[set] < 7) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    last_addr[set] = paddr;
    last_delta[set] = delta;
    streaming_flag[set] = (stream_conf[set] >= 5) ? 1 : 0;

    // --- PC signature ---
    uint8_t sig = pc_hash(PC);

    // --- Dead block predictor update ---
    if (hit) {
        // On hit: increment dead_ctr up to max
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
        // SHiP-lite: update PC reuse
        if (pc_table[pc_sig[set][way]] < 3) pc_table[pc_sig[set][way]]++;
        rrpv[set][way] = 0; // MRU
        return;
    } else {
        // On miss/fill: decay dead_ctr
        if (dead_ctr[set][way] > 0)
            dead_ctr[set][way]--;
    }

    // --- Insertion depth logic ---
    uint8_t ins_rrpv = 3; // default LRU

    // Streaming: bypass insertion (do not update block metadata)
    if (streaming_flag[set]) {
        ins_rrpv = 3; // Insert at LRU, as Champsim always inserts
    }
    // SHiP-lite: if PC shows frequent reuse, insert at MRU
    else if (pc_table[sig] >= 2) {
        ins_rrpv = 0;
    }
    // Dead block: if previous block at way was dead, insert at LRU
    else if (dead_ctr[set][way] == 0) {
        ins_rrpv = 3;
    }

    // Update block metadata
    pc_sig[set][way] = sig;
    rrpv[set][way] = ins_rrpv;
    dead_ctr[set][way] = 2; // neutral for new fill
    if (pc_table[sig] > 0) pc_table[sig]--; // decay PC reuse on fill

    // --- Periodic dead block decay ---
    global_fill_ctr++;
    if (global_fill_ctr % DEAD_DECAY_INTERVAL == 0)
        DeadBlockDecay();
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s])
            streaming_sets++;
    std::cout << "DBSSAR: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // PC reuse table
    std::cout << "DBSSAR: PC table (reuse counters): ";
    for (int i = 0; i < 32; ++i)
        std::cout << (int)pc_table[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed for this policy (decay on fill)
}