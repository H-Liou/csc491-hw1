#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits/line

// --- Dead-block predictor: 1 bit per line ---
uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 1 bit/line

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- DRRIP set-dueling: 64 leader sets, 10-bit PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 1 << (PSEL_BITS - 1); // Start in the middle
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(dead_block, 1, sizeof(dead_block)); // Predict dead on fill
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
    memset(leader_set_type, 2, sizeof(leader_set_type)); // Default: follower

    // Assign leader sets for set-dueling
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_set_type[i] = 0; // First 32: SRRIP leader
        leader_set_type[NUM_LEADER_SETS + i] = 1; // Next 32: BRRIP leader
    }
}

// --- Victim selection: prioritize dead blocks, then RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming phase: bypass cache (do not cache, return invalid way)
    if (streaming_flag[set])
        return LLC_WAYS; // Special: signal bypass

    // First, try to find a dead block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_block[set][way])
            return way;

    // Otherwise, standard RRIP victim selection
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
    // --- Streaming detector update (per set) ---
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- Dead-block predictor update ---
    if (hit) {
        dead_block[set][way] = 0; // Mark as live on hit
        rrpv[set][way] = 0;       // Promote to MRU
    } else {
        dead_block[set][way] = 1; // Predict dead on fill
        // Streaming: bypass, do not insert
        if (streaming_flag[set])
            return;

        // --- DRRIP insertion policy ---
        uint8_t ins_rrpv = 2; // SRRIP: insert at RRPV=2
        // Determine set type
        uint8_t set_type = leader_set_type[set];
        if (set_type == 0) { // SRRIP leader
            ins_rrpv = 2;
        } else if (set_type == 1) { // BRRIP leader
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at RRPV=3 31/32 times
        } else { // Follower
            ins_rrpv = (PSEL >= (1 << (PSEL_BITS - 1))) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
        }
        rrpv[set][way] = ins_rrpv;
    }

    // --- DRRIP set-dueling update ---
    uint8_t set_type = leader_set_type[set];
    if (set_type == 0) { // SRRIP leader
        if (hit && rrpv[set][way] == 2) // Hit on SRRIP-inserted line
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    } else if (set_type == 1) { // BRRIP leader
        if (hit && rrpv[set][way] == 3) // Hit on BRRIP-inserted line
            if (PSEL > 0) PSEL--;
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0, dead_lines = 0, live_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (streaming_flag[s]) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_block[s][w]) dead_lines++;
            else live_lines++;
        }
    }
    std::cout << "DRRIP-SDBP: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "DRRIP-SDBP: Dead lines: " << dead_lines << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "DRRIP-SDBP: Live lines: " << live_lines << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "DRRIP-SDBP: PSEL: " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "DRRIP-SDBP: Streaming sets: " << streaming_sets << std::endl;
}