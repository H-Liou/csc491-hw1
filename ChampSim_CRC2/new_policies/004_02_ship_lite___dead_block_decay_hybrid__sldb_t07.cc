#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];       // 2 bits/line

// --- Per-line dead-block approximation: 2 bits/line ---
uint8_t reuse_counter[LLC_SETS][LLC_WAYS]; // 2 bits/line

// --- SHiP-lite: 6-bit PC signature per line, 2-bit outcome table (2048 entries) ---
uint8_t pc_signature[LLC_SETS][LLC_WAYS];        // 6 bits/line
uint8_t pc_reuse_table[2048];                    // 2 bits/entry

// --- Helper: signature hash ---
inline uint16_t get_pc_sig(uint64_t PC) {
    // Use lower 6 bits XOR higher bits for compactness
    return ((PC ^ (PC >> 6)) & 0x3F);
}

// --- Helper: PC table index ---
inline uint16_t get_pc_index(uint64_t PC) {
    // Simple CRC or mask to 2048 entries
    return (PC ^ (PC >> 11)) & 0x7FF;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(reuse_counter, 0, sizeof(reuse_counter));
    memset(pc_signature, 0, sizeof(pc_signature));
    memset(pc_reuse_table, 1, sizeof(pc_reuse_table)); // neutral: unknown reuse
}

// --- Victim Selection: standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Replacement State Update ---
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
    // --- Get PC signature and table index ---
    uint8_t sig = get_pc_sig(PC);
    uint16_t pc_idx = get_pc_index(PC);

    // --- On hit: promote and update predictors ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        if (reuse_counter[set][way] < 3) reuse_counter[set][way]++;
        if (pc_reuse_table[pc_idx] < 3) pc_reuse_table[pc_idx]++;
    }
    else {
        // --- SHiP-lite prediction + dead-block ---
        // If PC reuse counter is low OR per-line reuse counter is low, predict dead
        bool predict_dead = (pc_reuse_table[pc_idx] <= 1) || (reuse_counter[set][way] == 0);

        // Insert at LRU if predicted dead, else distant (SRRIP)
        rrpv[set][way] = predict_dead ? 3 : 2;

        // Tag the line: update signature and reset reuse counter
        pc_signature[set][way] = sig;
        reuse_counter[set][way] = 1; // Start with weak prediction
    }

    // --- Periodic decay for adaptation ---
    static uint64_t access_count = 0;
    access_count++;
    if ((access_count & 0xFFF) == 0) { // Every 4096 accesses
        for (uint32_t i = 0; i < 2048; ++i)
            if (pc_reuse_table[i] > 0) pc_reuse_table[i]--;
        // Per-line counters: decay oldest set every period
        uint32_t s = (access_count >> 12) % LLC_SETS;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (reuse_counter[s][w] > 0) reuse_counter[s][w]--;
    }
}

// --- Stats ---
void PrintStats() {
    // Print PC reuse table histogram
    int dead = 0, live = 0, unknown = 0;
    for (uint32_t i = 0; i < 2048; ++i) {
        if (pc_reuse_table[i] == 0) dead++;
        else if (pc_reuse_table[i] == 3) live++;
        else unknown++;
    }
    std::cout << "SLDB: PC reuse table - dead:" << dead << " live:" << live << " unknown:" << unknown << std::endl;
}

void PrintStats_Heartbeat() {
    int reused = 0, inserted_dead = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (rrpv[s][w] == 0) reused++;
            else if (rrpv[s][w] == 3) inserted_dead++;
    std::cout << "SLDB: MRU lines:" << reused << " Dead-predicted:" << inserted_dead << std::endl;
}