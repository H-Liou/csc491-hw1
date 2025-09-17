#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];         // 2 bits/line: RRIP value
uint8_t dead_flag[LLC_SETS][LLC_WAYS];    // 1 bit/line: dead-block approximation

// --- DRRIP set-dueling: 64 leader sets, 10-bit PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));     // 10-bit PSEL, start at midpoint

uint8_t is_leader_set[LLC_SETS];          // 0: follower, 1: SRRIP leader, 2: BRRIP leader

// --- Streaming detector: per-set, 1 bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];         // 1 bit/set: 1 if streaming detected
uint32_t last_addr[LLC_SETS];             // 32 bits/set: last block address

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(dead_flag, 0, sizeof(dead_flag));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
    memset(is_leader_set, 0, sizeof(is_leader_set));

    // Assign leader sets: first half SRRIP, second half BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = (i * LLC_SETS) / NUM_LEADER_SETS;
        is_leader_set[set] = (i < NUM_LEADER_SETS/2) ? 1 : 2;
    }
}

// --- Victim selection: standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if streaming detected, always evict LRU (RRPV==3)
    if (streaming_flag[set]) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment RRPVs if none found
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
    }

    // Dead-block bypass: prefer evicting predicted dead blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_flag[set][way])
            return way;

    // Normal SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Replacement state update ---
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
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- Dead-block tracking ---
    if (hit) {
        rrpv[set][way] = 0; // promote to MRU
        dead_flag[set][way] = 0; // mark as alive
    } else {
        // On fill: set dead flag if streaming or if previous block was dead
        if (streaming_flag[set])
            dead_flag[set][way] = 1;
        else
            dead_flag[set][way] = 0;
    }

    // --- DRRIP insertion policy ---
    uint8_t ins_rrpv = 2; // SRRIP default (insert at RRPV=2)
    bool is_leader = (is_leader_set[set] != 0);

    if (is_leader_set[set] == 1) // SRRIP leader
        ins_rrpv = 2;
    else if (is_leader_set[set] == 2) // BRRIP leader
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: Insert at 2 with 1/32 probability, else 3
    else { // Follower: select based on PSEL
        ins_rrpv = (psel >= (1 << (PSEL_BITS-1))) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
    }

    // Streaming bypass: if streaming detected, always insert at LRU
    if (streaming_flag[set])
        rrpv[set][way] = 3;
    else
        rrpv[set][way] = ins_rrpv;

    // --- PSEL update: only on leader sets and on hits ---
    if (is_leader && hit) {
        if (is_leader_set[set] == 1 && psel < ((1 << PSEL_BITS) - 1))
            psel++;
        else if (is_leader_set[set] == 2 && psel > 0)
            psel--;
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "DRRIP-SBD: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;

    int dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_flag[s][w]) dead_blocks++;
    std::cout << "DRRIP-SBD: Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;

    std::cout << "DRRIP-SBD: PSEL value: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "DRRIP-SBD: Streaming sets: " << streaming_sets << std::endl;
}