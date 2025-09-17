#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Dead-block: 2-bit counter per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// DRRIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // midpoint
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower

// Streaming detector: per-set last addr/delta, 1-bit flag, 3-bit confidence
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_flag[LLC_SETS];
uint8_t stream_conf[LLC_SETS];

// Helper: assign leader sets (first NUM_LEADER_SETS/2 SRRIP, next half BRRIP)
void InitLeaderSets() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        leader_set_type[s] = 2; // follower
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        leader_set_type[i] = 0; // SRRIP leader
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = 1; // BRRIP leader
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU on reset
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(stream_conf, 0, sizeof(stream_conf));
    InitLeaderSets();
    PSEL = (1 << (PSEL_BITS - 1));
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
    // Streaming: prefer bypass (find invalid, else LRU)
    if (streaming_flag[set]) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        while (true) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] == 3)
                    return way;
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] < 3)
                    rrpv[set][way]++;
        }
    }

    // Dead-block: prefer block with dead_ctr==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;

    // RRIP fallback: pick block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
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

    // --- DRRIP insertion policy ---
    uint8_t ins_rrpv = 2; // SRRIP default: insert at distant (2)
    bool is_leader = (leader_set_type[set] < 2);

    if (streaming_flag[set]) {
        ins_rrpv = 3; // streaming: insert at LRU (simulate bypass)
    } else if (is_leader) {
        // Leader sets: fixed policy
        if (leader_set_type[set] == 0)      // SRRIP leader
            ins_rrpv = 2;
        else if (leader_set_type[set] == 1) // BRRIP leader
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: 1/32 at distant, else LRU
    } else {
        // Follower sets: use PSEL
        if (PSEL >= (1 << (PSEL_BITS - 1)))
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
    }

    // --- Dead-block counter update ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        dead_ctr[set][way] = 0; // reset dead counter on reuse
        // Update PSEL for leader sets
        if (is_leader) {
            if (leader_set_type[set] == 0)      // SRRIP leader
                if (ins_rrpv == 2) PSEL++;
            else if (leader_set_type[set] == 1) // BRRIP leader
                if (ins_rrpv == 3) PSEL--;
        }
        return;
    }

    // On fill/miss: set insertion RRPV
    rrpv[set][way] = ins_rrpv;

    // On eviction: if block was not reused, increment dead_ctr (max 3)
    if (!hit && rrpv[set][way] == 3) {
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s])
            streaming_sets++;
    std::cout << "DRRIP-DBS: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // Dead-block histogram
    uint64_t dead_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            dead_hist[dead_ctr[s][w]]++;
    std::cout << "DRRIP-DBS: Dead-block counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << dead_hist[i] << " ";
    std::cout << std::endl;

    // PSEL value
    std::cout << "DRRIP-DBS: PSEL final value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Decay dead-block counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] > 0)
                dead_ctr[s][w]--;
    // Optionally decay streaming confidence
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_conf[s] > 0)
            stream_conf[s]--;
}