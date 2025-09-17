#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
// 2 bits/line: RRIP
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 1 bit/line: streaming detected
uint8_t streaming[LLC_SETS][LLC_WAYS];

// 4 bits/line: last address delta (low bits, per block)
uint8_t addr_delta[LLC_SETS][LLC_WAYS];

// DRRIP set-dueling
#define LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1)); // init to middle value

// Mark sets as SRRIP or BRRIP leader sets
uint8_t set_type[LLC_SETS]; // 0: follower, 1: SRRIP leader, 2: BRRIP leader

// Helper: pick leader sets (first X as SRRIP, next X as BRRIP)
void InitSetTypes() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        set_type[s] = 0;
    for (uint32_t i = 0; i < LEADER_SETS; ++i)
        set_type[i] = 1; // SRRIP leader
    for (uint32_t i = LEADER_SETS; i < 2*LEADER_SETS; ++i)
        set_type[i] = 2; // BRRIP leader
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // distant
    memset(streaming, 0, sizeof(streaming));
    memset(addr_delta, 0, sizeof(addr_delta));
    psel = (1 << (PSEL_BITS - 1));
    InitSetTypes();
}

// --- Victim selection: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find first block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
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
    // --- Streaming Detection ---
    // Compute delta from previous address for this line
    uint64_t prev_addr = addr_delta[set][way];
    uint8_t last_delta = (uint8_t)((paddr >> 6) & 0xF); // 4 bits of block address
    uint8_t delta = (last_delta >= prev_addr) ? (last_delta - prev_addr) : (prev_addr - last_delta);

    // Detect monotonic delta (e.g., stride-1 or stride-N for several fills)
    if (!hit) {
        // If last 3 fills had same delta, set streaming bit
        static uint8_t delta_hist[LLC_SETS][LLC_WAYS][3] = {};
        delta_hist[set][way][2] = delta_hist[set][way][1];
        delta_hist[set][way][1] = delta_hist[set][way][0];
        delta_hist[set][way][0] = delta;

        if (delta_hist[set][way][0] == delta_hist[set][way][1] &&
            delta_hist[set][way][1] == delta_hist[set][way][2] &&
            delta_hist[set][way][0] != 0) // non-zero stride
            streaming[set][way] = 1;
        else
            streaming[set][way] = 0;

        addr_delta[set][way] = last_delta;
    }

    // --- DRRIP Insertion Depth ---
    // Determine which policy to use: SRRIP, BRRIP, or streaming
    uint8_t insert_rrpv = 2; // default distant

    if (set_type[set] == 1) { // SRRIP leader
        insert_rrpv = 2;
    }
    else if (set_type[set] == 2) { // BRRIP leader
        insert_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: 1/32 MRU, else LRU
    }
    else { // Follower set: use PSEL
        insert_rrpv = (psel >= (1 << (PSEL_BITS - 1))) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
    }

    // Streaming: if streaming detected, force LRU insert or bypass (RRPV=3)
    if (streaming[set][way]) {
        insert_rrpv = 3;
    }

    if (hit) {
        // On hit: promote to MRU
        rrpv[set][way] = 0;
    } else {
        // On fill: insert at computed depth
        rrpv[set][way] = insert_rrpv;
    }

    // --- Set-dueling PSEL Update ---
    if (!hit) {
        // Update PSEL based on whether hit/miss occurs in leader sets
        if (set_type[set] == 1) { // SRRIP leader
            if (hit && psel < ((1 << PSEL_BITS) - 1)) psel++;
        }
        else if (set_type[set] == 2) { // BRRIP leader
            if (hit && psel > 0) psel--;
        }
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "ASAD: PSEL = " << psel << std::endl;
    int streaming_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (streaming[s][w]) streaming_blocks++;
    std::cout << "Streaming blocks: " << streaming_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (streaming[s][w]) streaming_blocks++;
    std::cout << "ASAD: Streaming blocks: " << streaming_blocks << std::endl;
}