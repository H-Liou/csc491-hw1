#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- DRRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Dead-block Predictor ----
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Streaming Detector ----
uint16_t last_addr[LLC_SETS];         // Last address seen per set (lower 16 bits)
uint8_t stream_ctr[LLC_SETS];         // 2 bits per set: streaming confidence

// ---- DRRIP Set-dueling ----
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 512; // 10-bit selector, starts neutral
uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP

std::vector<uint32_t> leader_sets;

// Helper: is this set a leader set? Returns 0=SRRIP, 1=BRRIP, 2=Follower
uint8_t GetSetType(uint32_t set) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set)
            return leader_set_type[i];
    return 2; // Follower
}

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        last_addr[set] = 0;
        stream_ctr[set] = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // Default distant
            reuse_ctr[set][way] = 1; // Neutral
        }
    }
    // Leader sets: evenly spread across LLC_SETS
    leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = (i * LLC_SETS) / NUM_LEADER_SETS;
        leader_sets.push_back(set);
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // First half SRRIP, second half BRRIP
    }
    PSEL = 512;
}

// Streaming detector: update per access
inline void UpdateStreaming(uint32_t set, uint64_t paddr) {
    uint16_t addr_lo = paddr & 0xFFFF;
    int16_t delta = addr_lo - last_addr[set];
    if (delta == 64 || delta == -64) { // Typical cache line stride
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_addr[set] = addr_lo;
}

// Dead-block predictor: periodic decay (call every 100K accesses)
void DecayReuseCounters() {
    static uint64_t access_count = 0;
    access_count++;
    if (access_count % 100000 == 0) {
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (reuse_ctr[set][way] > 0)
                    reuse_ctr[set][way]--;
    }
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
    DecayReuseCounters();

    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Streaming bypass: if streaming confidence high, pick RRPV=3 block or random
    if (stream_ctr[set] == 3) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        return rand() % LLC_WAYS;
    }

    // Dead-block filter: prefer blocks with reuse_ctr==0 and RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 && reuse_ctr[set][way] == 0)
            return way;

    // Standard RRIP victim selection: prefer RRPV=3, then increment RRPVs
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
    UpdateStreaming(set, paddr);

    // Dead-block predictor update
    if (hit) {
        if (reuse_ctr[set][way] < 3)
            reuse_ctr[set][way]++;
    } else {
        // On miss, decay reuse counter for victim block
        if (reuse_ctr[set][way] > 0)
            reuse_ctr[set][way]--;
    }

    // Set-dueling: leader sets update PSEL
    uint8_t set_type = GetSetType(set);
    if (!hit && set_type < 2) {
        if (set_type == 0) { // SRRIP leader miss: increment PSEL
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        } else if (set_type == 1) { // BRRIP leader miss: decrement PSEL
            if (PSEL > 0) PSEL--;
        }
    }

    // Insertion policy
    uint8_t insert_rrpv = 2; // Default distant
    if (stream_ctr[set] == 3) {
        insert_rrpv = 3; // Streaming: bypass or distant
    } else if (reuse_ctr[set][way] == 0) {
        insert_rrpv = 3; // Dead-block: distant
    } else if (set_type == 0) { // SRRIP leader
        insert_rrpv = 0;
    } else if (set_type == 1) { // BRRIP leader
        insert_rrpv = (rand() % 32 == 0) ? 0 : 2; // Insert at 0 with 1/32 probability
    } else { // Follower
        insert_rrpv = (PSEL >= 512) ? 0 : ((rand() % 32 == 0) ? 0 : 2);
    }

    rrpv[set][way] = insert_rrpv;
    // On insertion, reset reuse counter to neutral
    reuse_ctr[set][way] = hit ? 3 : 1;
}

// Print end-of-simulation statistics
void PrintStats() {
    int streaming_sets = 0;
    int dead_blocks = 0;
    int live_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_ctr[set] == 3) streaming_sets++;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (reuse_ctr[set][way] == 0) dead_blocks++;
            if (reuse_ctr[set][way] == 3) live_blocks++;
        }
    std::cout << "ADB-DRRIP Policy: Adaptive Dead-Block + DRRIP Hybrid" << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Strongly live blocks: " << live_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_ctr[set] == 3) streaming_sets++;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}