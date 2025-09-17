#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV per block, 10-bit PSEL, 64 leader sets ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 1 << (PSEL_BITS - 1); // 10-bit saturating counter
uint8_t is_leader_set[LLC_SETS]; // 0: normal, 1: SRRIP leader, 2: BRRIP leader

uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: 2-bit per set, last address/delta per set ---
uint8_t stream_ctr[LLC_SETS];
uint64_t last_addr[LLC_SETS];
uint64_t last_delta[LLC_SETS];

// --- Dead-block predictor: 2-bit per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// --- Periodic decay for dead-block predictor ---
uint64_t access_counter = 0;
const uint64_t DECAY_PERIOD = 100000;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(is_leader_set, 0, sizeof(is_leader_set));
    // Assign leader sets for set-dueling
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = 1; // SRRIP leader
        is_leader_set[LLC_SETS - 1 - i] = 2; // BRRIP leader
    }
    PSEL = 1 << (PSEL_BITS - 1);
}

// --- Find victim: Prefer dead blocks, else SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // 1. Prefer block with dead_ctr==0 and RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 && dead_ctr[set][way] == 0)
            return way;
    // 2. Next, any block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
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

    // --- Streaming detector: update on fill (miss only) ---
    if (!hit) {
        uint64_t delta = (last_addr[set] == 0) ? 0 : (paddr - last_addr[set]);
        if (last_addr[set] != 0 && delta == last_delta[set] && delta != 0) {
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
        last_delta[set] = delta;
        last_addr[set] = paddr;
    }

    // --- Dead-block predictor: update ---
    if (hit) {
        // On hit, block is reused: reset dead_ctr
        dead_ctr[set][way] = 3;
        rrpv[set][way] = 0;
        return;
    } else {
        // On miss, decrement dead_ctr (not below 0)
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
    }

    // --- DRRIP insertion policy selection ---
    uint8_t ins_rrpv = 2; // SRRIP default: insert at RRPV=2

    // Set-dueling for DRRIP
    if (is_leader_set[set] == 1) { // SRRIP leader
        ins_rrpv = 2;
    } else if (is_leader_set[set] == 2) { // BRRIP leader
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at RRPV=2 with 1/32 probability, else 3
    } else {
        // Follower sets: use PSEL
        if (PSEL >= (1 << (PSEL_BITS - 1)))
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
    }

    // --- Streaming sets: override to distant insert/bypass ---
    if (stream_ctr[set] >= 2) {
        ins_rrpv = 3; // Streaming detected: insert at distant
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    // Dead-block predictor: new block starts at 1 (likely dead unless reused soon)
    dead_ctr[set][way] = 1;

    // --- On eviction: update DRRIP PSEL for leader sets ---
    if (is_leader_set[set] == 1) { // SRRIP leader
        if (hit) {
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        } else {
            if (PSEL > 0) PSEL--;
        }
    } else if (is_leader_set[set] == 2) { // BRRIP leader
        if (hit) {
            if (PSEL > 0) PSEL--;
        } else {
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        }
    }

    // --- Periodic decay for dead-block predictor ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Streaming-Aware Dead-Block Hybrid: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << "/" << LLC_SETS << std::endl;

    uint32_t dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w] == 0) dead_blocks++;
            total_blocks++;
        }
    std::cout << "Dead blocks at end: " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and dead block histogram
}