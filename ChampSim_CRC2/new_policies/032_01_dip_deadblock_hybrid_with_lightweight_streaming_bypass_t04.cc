#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//--------------------------------------------
// DIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t psel = PSEL_MAX / 2;
uint8_t is_leader_set[LLC_SETS];

// Dead-block predictor: 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// Streaming detector: 2 bits per set, last address per set
uint8_t stream_ctr[LLC_SETS];
uint64_t last_addr[LLC_SETS];
#define STREAM_THRESHOLD 3

// RRIP bits: 2 per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Distant for all blocks
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    // Assign leader sets for DIP: first 32 as LIP, next 32 as BIP
    memset(is_leader_set, 0, sizeof(is_leader_set));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        is_leader_set[i] = (i < NUM_LEADER_SETS/2) ? 1 : 2; // 1=LIP, 2=BIP
}

//--------------------------------------------
// Streaming detector update
inline void update_streaming(uint32_t set, uint64_t paddr) {
    uint64_t last = last_addr[set];
    uint64_t delta = (last == 0) ? 0 : (paddr > last ? paddr - last : last - paddr);
    if (last != 0 && (delta == 64 || delta == 128)) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_addr[set] = paddr;
}

//--------------------------------------------
// Dead-block decay (called every 100K accesses, for example)
void DecayDeadCounters() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] > 0)
                dead_ctr[s][w]--;
}

//--------------------------------------------
// Find victim in the set (prefer dead blocks)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if streaming detected, always evict block with rrpv==3
    if (stream_ctr[set] >= STREAM_THRESHOLD) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
    }

    // Dead-block preference: evict block with dead_ctr==3 (most dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;

    // Otherwise, RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
    return 0; // Should not reach
}

//--------------------------------------------
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
    //--- Streaming detector update
    update_streaming(set, paddr);

    //--- Dead-block update
    if (hit) {
        dead_ctr[set][way] = 0; // Reset on reuse
        rrpv[set][way] = 0;     // Promote on hit
    } else {
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    //--- DIP insertion depth control
    uint8_t ins_rrpv = 3; // Default: distant (LIP)
    bool is_lip_leader = (set < NUM_LEADER_SETS/2);
    bool is_bip_leader = (set >= NUM_LEADER_SETS/2 && set < NUM_LEADER_SETS);

    // Streaming bypass: If streaming detected, do not insert, just mark as distant
    if (stream_ctr[set] >= STREAM_THRESHOLD) {
        rrpv[set][way] = 3;
        return;
    }

    // DIP logic
    if (is_lip_leader) {
        ins_rrpv = 3; // LIP: insert at distant
    } else if (is_bip_leader) {
        ins_rrpv = (rand() % 32 == 0) ? 1 : 3; // BIP: insert at MRU with low probability
    } else {
        // Follower sets: use PSEL
        ins_rrpv = (psel >= (PSEL_MAX/2)) ? 3 : ((rand() % 32 == 0) ? 1 : 3);
    }
    rrpv[set][way] = ins_rrpv;

    //--- DIP PSEL update: Only on misses in leader sets
    if (!hit) {
        if (is_lip_leader && psel < PSEL_MAX)
            psel++;
        else if (is_bip_leader && psel > 0)
            psel--;
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DIP-Deadblock Hybrid: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= STREAM_THRESHOLD)
            streaming_sets++;
    std::cout << "Sets with streaming detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count or dead-block distribution
}