#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits per block
uint8_t sig[LLC_SETS][LLC_WAYS];         // 4 bits per block (PC signature)
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS];   // 2 bits per block

// --- SHiP-lite signature table ---
struct SHIPEntry {
    uint8_t reuse; // 2 bits: saturating counter
};
SHIPEntry ship_table[LLC_SETS * LLC_WAYS]; // 2048*16 = 32768 entries, 2 bytes/entry

// --- Streaming detector: per-set recent address delta ---
int32_t last_addr[LLC_SETS];    // Last address seen in set
int32_t last_delta[LLC_SETS];   // Last delta
uint8_t stream_score[LLC_SETS]; // 8 bits per set

// Helper: hash PC to 4 bits
inline uint8_t pc_sig(uint64_t PC) {
    return (PC ^ (PC >> 4) ^ (PC >> 8)) & 0xF;
}

void InitReplacementState() {
    // Per-block metadata
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            sig[set][way] = 0;
            reuse_ctr[set][way] = 1;
        }
    // SHiP table
    memset(ship_table, 1, sizeof(ship_table)); // neutral
    // Streaming detector
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_score, 0, sizeof(stream_score));
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
    // Streaming bypass: if stream_score high, bypass (return -1)
    if (stream_score[set] >= 8) {
        return LLC_WAYS; // convention: bypass, don't insert
    }
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Prefer block with low reuse_ctr
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (reuse_ctr[set][way] == 0)
            return way;
    // Classic RRIP victim selection
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
    // --- Streaming detector ---
    int32_t addr = (int32_t)(paddr >> 6); // block address
    int32_t delta = addr - last_addr[set];
    if (last_addr[set] != 0) {
        if (delta == last_delta[set] && delta != 0) {
            if (stream_score[set] < 15) stream_score[set]++;
        } else {
            if (stream_score[set] > 0) stream_score[set]--;
        }
    }
    last_delta[set] = delta;
    last_addr[set] = addr;

    // --- SHiP-lite signature learning ---
    uint8_t signature = pc_sig(PC);
    uint32_t ship_idx = (set * LLC_WAYS) + way;
    if (hit) {
        // Block reused: increment per-block and signature table counter
        if (reuse_ctr[set][way] < 3) reuse_ctr[set][way]++;
        if (ship_table[ship_idx].reuse < 3) ship_table[ship_idx].reuse++;
        rrpv[set][way] = 0; // protect
    } else {
        // Miss: decay per-block and signature table
        if (reuse_ctr[set][way] > 0) reuse_ctr[set][way]--;
        if (ship_table[ship_idx].reuse > 0) ship_table[ship_idx].reuse--;
    }

    // --- Periodic decay of reuse counters ---
    static uint64_t access_count = 0;
    access_count++;
    if (access_count % (LLC_SETS * LLC_WAYS) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_ctr[s][w] > 0)
                    reuse_ctr[s][w]--;
        for (uint32_t i = 0; i < LLC_SETS * LLC_WAYS; ++i)
            if (ship_table[i].reuse > 0)
                ship_table[i].reuse--;
    }

    // --- Insertion policy ---
    // If streaming detected, bypass or insert at distant
    if (stream_score[set] >= 8) {
        // Bypass: do not insert (caller must check for LLC_WAYS return)
        return;
    }
    // Otherwise, SHiP-lite: consult signature table
    if (ship_table[ship_idx].reuse >= 2) {
        rrpv[set][way] = 0; // MRU
    } else {
        rrpv[set][way] = 2; // distant
    }
    sig[set][way] = signature;
    // On miss, reset reuse_ctr to neutral
    if (!hit)
        reuse_ctr[set][way] = 1;
}

// Print end-of-simulation statistics
void PrintStats() {
    int live_blocks = 0, dead_blocks = 0, bypass_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (stream_score[set] >= 8) bypass_sets++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (reuse_ctr[set][way] == 3) live_blocks++;
            if (reuse_ctr[set][way] == 0) dead_blocks++;
        }
    }
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid Policy" << std::endl;
    std::cout << "Live blocks: " << live_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Bypass sets (streaming detected): " << bypass_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int live_blocks = 0, bypass_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (stream_score[set] >= 8) bypass_sets++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (reuse_ctr[set][way] == 3) live_blocks++;
    }
    std::cout << "Live blocks (heartbeat): " << live_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Bypass sets (stream): " << bypass_sets << "/" << LLC_SETS << std::endl;
}