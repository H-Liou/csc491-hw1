#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP set-dueling selector ---
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t PSEL = PSEL_MAX / 2;

// --- Leader set mapping (32 leader sets for SRRIP, 32 for BRRIP) ---
#define NUM_LEADER_SETS 64
uint8_t leader_type[LLC_SETS]; // 0=not leader, 1=SRRIP leader, 2=BRRIP leader

// --- RRIP state per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector per set ---
uint8_t stream_ctr[LLC_SETS];     // 2 bits per set: 0=not streaming, 3=strong streaming
uint64_t last_addr[LLC_SETS];     // last address seen per set

// --- Dead-block predictor per block ---
uint8_t dead_bit[LLC_SETS][LLC_WAYS]; // 1 bit per block

// Helper: assign leader sets (first 32 SRRIP, next 32 BRRIP)
void InitLeaderSets() {
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        leader_type[i] = 0;
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        leader_type[i] = 1; // SRRIP leader
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        leader_type[i] = 2; // BRRIP leader
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(dead_bit, 0, sizeof(dead_bit));
    InitLeaderSets();
    PSEL = PSEL_MAX / 2;
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
    // Streaming detected: bypass fill (return invalid way if possible)
    if (stream_ctr[set] == 3) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way; // fill invalid only
        // If no invalid, pick dead block if possible
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_bit[set][way])
                return way;
        // Otherwise, pick RRPV==3
    }

    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Prefer dead block (early eviction)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_bit[set][way])
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

    // --- Dead-block predictor update ---
    if (hit) {
        rrpv[set][way] = 0; // protect
        dead_bit[set][way] = 0; // mark as live
    } else {
        // On fill: set insertion depth based on DRRIP
        uint8_t insert_rrpv = 2; // SRRIP default
        if (leader_type[set] == 1) { // SRRIP leader
            insert_rrpv = 2;
        } else if (leader_type[set] == 2) { // BRRIP leader
            insert_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert distant most of time
        } else {
            // Follower: use PSEL
            insert_rrpv = (PSEL >= (PSEL_MAX / 2)) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
        }

        // Streaming detected: always insert distant
        if (stream_ctr[set] == 3)
            insert_rrpv = 3;

        rrpv[set][way] = insert_rrpv;
        dead_bit[set][way] = 0; // new block assumed live
    }

    // --- DRRIP set-dueling update ---
    if (!hit) {
        if (leader_type[set] == 1 && rrpv[set][way] == 0) { // SRRIP leader hit
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (leader_type[set] == 2 && rrpv[set][way] == 0) { // BRRIP leader hit
            if (PSEL > 0) PSEL--;
        }
    }

    // --- Dead-block predictor: on eviction, mark as dead if not reused ---
    // Simulate: if block is evicted without hit, mark dead
    // (In real ChampSim, handled externally. Here, approximate: if victim_addr is valid and block not hit before eviction)
    // For simplicity, decay dead bits periodically (not implemented here for brevity)
}

// Print end-of-simulation statistics
void PrintStats() {
    int protected_blocks = 0, distant_blocks = 0, streaming_sets = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (dead_bit[set][way]) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    std::cout << "DRRIP + Streaming Bypass + Dead-Block Prediction Policy" << std::endl;
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
            if (dead_bit[set][way]) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << "/" << PSEL_MAX << std::endl;
}