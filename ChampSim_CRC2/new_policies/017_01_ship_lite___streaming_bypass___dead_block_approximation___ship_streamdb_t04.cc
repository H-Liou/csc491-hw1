#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite Metadata ---
// 6-bit PC signature per block
static uint8_t block_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block

// 2-bit outcome counter per signature (table size: 2048 entries)
static uint8_t signature_outcome[2048]; // 2 bits per signature

// --- Dead-block Approximation ---
// 2-bit dead-block counter per block (decayed periodically)
static uint8_t dead_block_counter[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming Detector ---
// For each set: last address seen, last delta, streaming streak counter
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_streak[LLC_SETS]; // up to 15

// --- RRIP Metadata ---
// 2-bit RRPV per block
static uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Helper: hash PC to 6-bit signature
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Helper: hash signature to outcome table index (11 bits)
inline uint16_t SigIdx(uint8_t sig) {
    return sig; // direct mapping for 64 entries, or (sig ^ (sig << 3)) & 0x7FF for 2048
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(block_signature, 0, sizeof(block_signature));
    memset(signature_outcome, 1, sizeof(signature_outcome)); // weak reuse by default
    memset(dead_block_counter, 0, sizeof(dead_block_counter));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_streak, 0, sizeof(stream_streak));
}

// --- Streaming Detector ---
// Returns true if streaming detected (>4 consecutive accesses with same delta)
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    uint64_t addr = paddr >> 6; // line granularity
    int64_t delta = addr - last_addr[set];
    if (stream_streak[set] >= 4 && delta == last_delta[set] && delta != 0)
        return true;
    return false;
}

// --- Find victim: RRIP + dead-block bias ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV==3 and dead-block counter==0
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3 && dead_block_counter[set][way] == 0)
                return way;
        // Next, any block with RRPV==3
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Aging: increment all RRPVs < 3
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
}

// --- Update replacement state ---
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
    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);
    uint16_t sig_idx = SigIdx(sig);

    // --- Streaming detector update ---
    uint64_t addr = paddr >> 6;
    int64_t delta = addr - last_addr[set];
    if (delta != 0 && delta == last_delta[set])
        stream_streak[set] = (stream_streak[set] < 15) ? stream_streak[set] + 1 : 15;
    else
        stream_streak[set] = 0;
    last_delta[set] = delta;
    last_addr[set] = addr;

    // --- Dead-block counter decay (every 4096 accesses) ---
    static uint64_t access_count = 0;
    if ((access_count++ & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_block_counter[s][w] > 0)
                    --dead_block_counter[s][w];
    }

    // --- On hit: promote to MRU, update outcome counter, dead-block counter ---
    if (hit) {
        rrpv[set][way] = 0;
        if (signature_outcome[sig_idx] < 3)
            ++signature_outcome[sig_idx];
        if (dead_block_counter[set][way] < 3)
            ++dead_block_counter[set][way];
        return;
    }

    // --- On miss: update outcome counter for victim block, decay dead-block counter ---
    uint8_t victim_sig = block_signature[set][way];
    uint16_t victim_idx = SigIdx(victim_sig);
    if (signature_outcome[victim_idx] > 0)
        --signature_outcome[victim_idx];
    if (dead_block_counter[set][way] > 0)
        --dead_block_counter[set][way];

    // --- Streaming bypass logic ---
    if (IsStreaming(set, paddr)) {
        // Streaming detected: bypass cache (do not insert)
        rrpv[set][way] = 3;
        block_signature[set][way] = sig;
        dead_block_counter[set][way] = 0;
        return;
    }

    // --- SHiP insertion depth ---
    // If signature outcome counter is strong (>=2), insert at RRPV=0 (MRU)
    // Else, insert at RRPV=3 (LRU) unless dead-block counter is strong (>=2)
    if (signature_outcome[sig_idx] >= 2 || dead_block_counter[set][way] >= 2) {
        rrpv[set][way] = 0;
    } else {
        rrpv[set][way] = 3;
    }
    block_signature[set][way] = sig;
    // Reset dead-block counter on new insertion
    dead_block_counter[set][way] = 0;
}

// --- Print statistics ---
void PrintStats() {
    uint32_t strong_sig = 0;
    for (uint32_t i = 0; i < 2048; ++i)
        if (signature_outcome[i] >= 2) ++strong_sig;
    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block_counter[s][w] == 0) ++dead_blocks;
    std::cout << "SHiP-StreamDB Policy\n";
    std::cout << "Strong reuse signatures: " << strong_sig << " / 2048\n";
    std::cout << "Dead blocks (counter==0): " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << "\n";
}

// --- Heartbeat stats ---
void PrintStats_Heartbeat() {
    // Optional: print streaming streak distribution
}