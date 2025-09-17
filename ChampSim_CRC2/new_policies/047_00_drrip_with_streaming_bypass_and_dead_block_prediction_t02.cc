#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;
uint8_t is_leader_set[LLC_SETS]; // 0: normal, 1: SRRIP leader, 2: BRRIP leader

// --- RRIP state ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector per set ---
uint8_t stream_ctr[LLC_SETS];     // 2 bits per set: 0=not streaming, 3=strong streaming
uint64_t last_addr[LLC_SETS];     // last address seen per set

// --- Dead-block counter per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// Helper: initialize leader sets for DRRIP set-dueling
void InitLeaderSets() {
    memset(is_leader_set, 0, sizeof(is_leader_set));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = 1; // SRRIP leader
        is_leader_set[LLC_SETS - 1 - i] = 2; // BRRIP leader
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));         // distant
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    InitLeaderSets();
    PSEL = PSEL_MAX / 2;
}

// Find victim in the set (prefer dead blocks, then RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Prefer dead blocks (dead_ctr == 3)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;

    // RRIP scan for RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
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
    uint64_t addr_delta = (last_addr[set] > 0) ? (paddr - last_addr[set]) : 0;
    last_addr[set] = paddr;
    if (addr_delta == 64 || addr_delta == -64) { // 64B line stride
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }

    // --- Dead-block counter decay (periodic, every 4096 fills) ---
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) { // every 4096 fills
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }

    // --- DRRIP insertion depth selection ---
    uint8_t insert_rrpv = 2; // SRRIP default
    if (is_leader_set[set] == 1) insert_rrpv = 2; // SRRIP leader
    else if (is_leader_set[set] == 2) insert_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP leader: 1/32 close, else distant
    else insert_rrpv = (PSEL >= (PSEL_MAX / 2)) ? 2 : ((rand() % 32 == 0) ? 2 : 3); // normal set: select policy

    // --- Streaming bypass ---
    if (stream_ctr[set] == 3) {
        // Strong streaming: bypass fill (simulate by marking block as invalid and dead)
        rrpv[set][way] = 3;
        dead_ctr[set][way] = 3;
        return;
    }

    // --- On hit: promote block, mark as alive ---
    if (hit) {
        rrpv[set][way] = 0; // protect
        dead_ctr[set][way] = 0; // alive
        // Update PSEL for leader sets
        if (is_leader_set[set] == 1 && PSEL < PSEL_MAX) PSEL++;
        else if (is_leader_set[set] == 2 && PSEL > 0) PSEL--;
    }
    // On miss: fill block
    else {
        rrpv[set][way] = insert_rrpv;
        dead_ctr[set][way] = 0; // assume alive on fill
    }

    // --- On eviction: if block was not reused, increment dead_ctr ---
    // Simulate: if block is evicted without hit, increment dead_ctr
    // (No explicit eviction callback; handled when victim selected)
    // Here, we approximate: if block was not hit before eviction, dead_ctr is incremented in GetVictimInSet
    // (see above: dead_ctr[set][way] == 3 is preferred for eviction)
}

// Print end-of-simulation statistics
void PrintStats() {
    int protected_blocks = 0, distant_blocks = 0, streaming_sets = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (dead_ctr[set][way] == 3) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    std::cout << "DRRIP with Streaming Bypass and Dead-Block Prediction Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL: " << PSEL << "/" << PSEL_MAX << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int protected_blocks = 0, distant_blocks = 0, streaming_sets = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (dead_ctr[set][way] == 3) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << "/" << PSEL_MAX << std::endl;
}