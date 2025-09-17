#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits/line
uint8_t sig[LLC_SETS][LLC_WAYS];         // 6 bits/line: PC signature

// --- SHiP outcome table: 4096 entries, 2 bits each ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_TABLE_SIZE];     // 2 bits per signature

// --- Streaming detector: per-set, 1 bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];        // 1 bit/set: 1 if streaming detected
uint32_t last_addr[LLC_SETS];            // 32 bits/set: last block address

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(sig, 0, sizeof(sig));
    memset(ship_table, 1, sizeof(ship_table)); // Weakly alive
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
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
        // Try again
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
    }

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

    // --- SHiP signature ---
    uint8_t pc_sig = (uint8_t)(PC ^ (PC >> 6)) & ((1 << SHIP_SIG_BITS) - 1);

    if (hit) {
        // On hit: promote to MRU, update SHiP outcome
        rrpv[set][way] = 0;
        ship_table[sig[set][way]] = std::min(ship_table[sig[set][way]] + 1, 3); // saturate
    } else {
        // On fill: assign signature
        sig[set][way] = pc_sig;

        // Streaming bypass: if streaming detected, insert at distant RRPV or bypass
        if (streaming_flag[set]) {
            rrpv[set][way] = 3; // insert at LRU
            // Optionally: bypass (simulate by not updating the block, but here just insert at LRU)
        } else {
            // SHiP outcome: if signature counter is high, insert at MRU; else at LRU
            if (ship_table[pc_sig] >= 2)
                rrpv[set][way] = 0; // MRU
            else
                rrpv[set][way] = 3; // LRU
        }
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-SB: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    int reused = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i] >= 2) reused++;
    std::cout << "SHiP-SB: Reused signatures: " << reused << " / " << SHIP_TABLE_SIZE << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-SB: Streaming sets: " << streaming_sets << std::endl;
}