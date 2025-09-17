#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-Lite: 6-bit PC signature per block ----
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// ---- SHiP outcome table: 64 signatures per set, 2 bits per entry ----
#define SHIP_SIGS_PER_SET 64
uint8_t ship_ctr[LLC_SETS][SHIP_SIGS_PER_SET]; // 2 bits per signature

// ---- Streaming detector: 2-bit per set ----
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set
uint64_t last_addr[LLC_SETS]; // last address seen per set

// Helper: hash PC to 6-bit signature
inline uint8_t GetPCSig(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Helper: hash block signature to outcome table index
inline uint8_t SigIdx(uint8_t sig) {
    return sig & (SHIP_SIGS_PER_SET - 1);
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // distant
            pc_sig[set][way] = 0;
        }
        for (uint32_t i = 0; i < SHIP_SIGS_PER_SET; ++i)
            ship_ctr[set][i] = 1; // neutral
        stream_ctr[set] = 0;
        last_addr[set] = 0;
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // RRIP victim selection: prefer RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment all RRPVs
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
    uint64_t addr = paddr >> 6; // block address
    uint64_t delta = (last_addr[set] > 0) ? (addr > last_addr[set] ? addr - last_addr[set] : last_addr[set] - addr) : 0;
    if (last_addr[set] > 0) {
        if (delta == 1 || delta == 0) { // monotonic or repeated
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
    }
    last_addr[set] = addr;

    // --- SHiP signature extraction ---
    uint8_t sig = GetPCSig(PC);
    uint8_t idx = SigIdx(sig);

    // --- Update SHiP outcome table ---
    if (hit) {
        if (ship_ctr[set][idx] < 3) ship_ctr[set][idx]++;
    } else {
        if (ship_ctr[set][idx] > 0) ship_ctr[set][idx]--;
    }

    // --- Insertion policy ---
    // If streaming detected, insert at distant RRPV or bypass (if strong streaming)
    bool streaming = (stream_ctr[set] >= 2);

    if (streaming) {
        // If strong streaming, bypass (do not insert, just mark as invalid)
        rrpv[set][way] = 3;
        pc_sig[set][way] = sig;
        // Optionally, could skip insertion entirely, but for simplicity, just make block distant.
    } else {
        // SHiP-guided insertion: if signature outcome counter is high, insert at MRU; else distant
        if (ship_ctr[set][idx] >= 2) {
            rrpv[set][way] = 0; // MRU insertion
        } else {
            rrpv[set][way] = 2; // distant
        }
        pc_sig[set][way] = sig;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int mru_blocks = 0, distant_blocks = 0;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) mru_blocks++;
            if (rrpv[set][way] == 2) distant_blocks++;
        }
        if (stream_ctr[set] >= 2) streaming_sets++;
    }
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid Policy" << std::endl;
    std::cout << "MRU blocks: " << mru_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_ctr[set] >= 2) streaming_sets++;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}