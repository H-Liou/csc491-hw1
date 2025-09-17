#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t PSEL = PSEL_MAX / 2; // 10-bit global PSEL
#define DUEL_SETS_SR 32
#define DUEL_SETS_BR 32
bool is_duel_set_sr[LLC_SETS] = {0};
bool is_duel_set_br[LLC_SETS] = {0};

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];  // 2 bits per block: dead-block approximation

// --- Streaming detector per set ---
uint8_t stream_ctr[LLC_SETS];        // 2 bits per set: 0=not streaming, 3=strong streaming
uint64_t last_addr[LLC_SETS];        // last address seen per set

// Helper: initialize leader sets for DRRIP set-dueling
void InitLeaderSets() {
    for (uint32_t i = 0; i < DUEL_SETS_SR; ++i)
        is_duel_set_sr[i] = true;
    for (uint32_t i = 0; i < DUEL_SETS_BR; ++i)
        is_duel_set_br[LLC_SETS - 1 - i] = true;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));         // distant
    memset(dead_ctr, 0, sizeof(dead_ctr)); // all blocks start "alive"
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    InitLeaderSets();
    PSEL = PSEL_MAX / 2;
}

// Find victim in the set (prefer blocks likely dead, else classic RRIP)
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

    // First, try to find block with RRPV==3 and dead_ctr==3 (likely dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 && dead_ctr[set][way] == 3)
            return way;

    // Classic RRIP scan
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

    // --- Dead-block counter decay: every 1024 fills, decay all counters in set ---
    static uint64_t global_fill_count = 0;
    global_fill_count++;
    if ((global_fill_count & 1023) == 0) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[set][w] > 0)
                dead_ctr[set][w]--;
    }

    // --- DRRIP insertion policy selection ---
    bool use_srrip = false;
    if (is_duel_set_sr[set])
        use_srrip = true;
    else if (is_duel_set_br[set])
        use_srrip = false;
    else
        use_srrip = (PSEL >= (PSEL_MAX / 2));

    // --- On hit: protect block, mark as 'alive' ---
    if (hit) {
        rrpv[set][way] = 0; // protect
        dead_ctr[set][way] = 0;
        // Update PSEL for leader sets
        if (is_duel_set_sr[set])
            if (PSEL < PSEL_MAX) PSEL++;
        if (is_duel_set_br[set])
            if (PSEL > 0) PSEL--;
    }
    // --- On miss: control insertion ---
    else {
        // Streaming detected: bypass or insert at distant RRPV
        if (stream_ctr[set] == 3) {
            // If bypass allowed, invalidate (simulate bypass); else insert at RRPV=3
            rrpv[set][way] = 3;
            dead_ctr[set][way] = 3; // mark as likely dead
        } else {
            // DRRIP: insert at RRPV=2 (SRRIP) or RRPV=3 (BRRIP, 1/32 probability insert at RRPV=2)
            if (use_srrip)
                rrpv[set][way] = 2;
            else
                rrpv[set][way] = ((rand() & 31) == 0) ? 2 : 3;
            dead_ctr[set][way] = 0; // new block, not dead
        }
    }
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
    std::cout << "DRRIP-DeadBlock Hybrid with Streaming Bypass Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value: " << PSEL << "/" << PSEL_MAX << std::endl;
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
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value (heartbeat): " << PSEL << "/" << PSEL_MAX << std::endl;
}