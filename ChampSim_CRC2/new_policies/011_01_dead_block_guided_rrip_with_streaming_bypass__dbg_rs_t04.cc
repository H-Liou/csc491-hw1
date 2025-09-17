#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Dead-block reuse counter: 2 bits/block
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set, tracks last address and delta, 1-bit streaming flag
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_flag[LLC_SETS]; // 1 bit/set

// Streaming detector: per-set, 2-bit confidence counter
uint8_t stream_conf[LLC_SETS]; // 2 bits/set

// Heartbeat counter for periodic decay
uint64_t heartbeat = 0;

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(reuse_ctr, 2, sizeof(reuse_ctr)); // weakly reused
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(stream_conf, 0, sizeof(stream_conf));
    heartbeat = 0;
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
    // If streaming detected, prefer blocks with RRPV==3
    if (streaming_flag[set]) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // If none, increment RRPV and retry
        while (true) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] == 3)
                    return way;
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] < 3)
                    rrpv[set][way]++;
        }
    }

    // Otherwise, prefer blocks with low reuse counter and RRPV==3
    uint32_t victim = LLC_WAYS;
    uint8_t min_reuse = 4;
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (rrpv[set][way] == 3 && reuse_ctr[set][way] < min_reuse) {
            victim = way;
            min_reuse = reuse_ctr[set][way];
        }
    }
    if (victim < LLC_WAYS)
        return victim;

    // If none, normal RRIP victim selection
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
        if (stream_conf[set] < 3) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    last_addr[set] = paddr;
    last_delta[set] = delta;
    streaming_flag[set] = (stream_conf[set] >= 2) ? 1 : 0;

    // --- Dead-block reuse counter update ---
    if (hit) {
        // On hit, increment reuse counter (max 3), set RRPV to MRU
        if (reuse_ctr[set][way] < 3) reuse_ctr[set][way]++;
        rrpv[set][way] = 0;
        return;
    }

    // On miss/fill
    uint8_t ins_rrpv;
    if (streaming_flag[set]) {
        // Streaming: bypass if possible (insert at LRU)
        ins_rrpv = 3;
    } else if (reuse_ctr[set][way] >= 2) {
        // If block previously reused, insert at MRU
        ins_rrpv = 0;
    } else {
        // Otherwise, insert at LRU
        ins_rrpv = 3;
    }

    // Reset reuse counter for new fill
    reuse_ctr[set][way] = 0;
    rrpv[set][way] = ins_rrpv;

    // --- Periodic decay of reuse counters to approximate deadness ---
    heartbeat++;
    if ((heartbeat & 0xFFF) == 0) { // every 4096 fills, decay all reuse counters
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_ctr[s][w] > 0)
                    reuse_ctr[s][w]--;
    }
}

void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s])
            streaming_sets++;
    std::cout << "DBG-RS: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // Dead-block counters summary
    uint64_t reused = 0, dead = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (reuse_ctr[s][w] >= 2) reused++;
            else dead++;
    std::cout << "DBG-RS: Reused blocks: " << reused << ", Dead blocks: " << dead << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print streaming set ratio or reuse histogram
}