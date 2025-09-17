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

// --- Dead-block approximation ---
// 2-bit dead-block counter per block
static uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector ---
// For each set, track last address and last delta (8 bits/set)
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_score[LLC_SETS]; // 8 bits per set

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
    memset(dead_block, 0, sizeof(dead_block));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_score, 0, sizeof(stream_score));
}

// --- Streaming detector ---
// Returns true if streaming detected for this set
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    if (delta == last_delta[set] && delta != 0) {
        if (stream_score[set] < 255) stream_score[set]++;
    } else {
        if (stream_score[set] > 0) stream_score[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
    // Streaming if score >= 32 (arbitrary threshold)
    return stream_score[set] >= 32;
}

// --- Find victim: prefer dead blocks, else RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, try to evict block with dead_block==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_block[set][way] == 3)
            return way;
    // Next, standard RRIP: find block with RRPV==3
    while (true) {
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
    // --- Streaming detector ---
    bool streaming = IsStreaming(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);
    uint16_t sig_idx = SigIdx(sig);

    // --- Dead-block counter decay: every 4096 accesses, halve all counters ---
    static uint64_t access_count = 0;
    if ((++access_count & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_block[s][w] >>= 1;
    }

    // On hit: promote to MRU, update outcome counter, reset dead-block counter
    if (hit) {
        rrpv[set][way] = 0;
        if (signature_outcome[sig_idx] < 3)
            ++signature_outcome[sig_idx];
        dead_block[set][way] = 0;
        return;
    }

    // On miss: update outcome counter for victim block, increment dead-block counter
    uint8_t victim_sig = block_signature[set][way];
    uint16_t victim_idx = SigIdx(victim_sig);
    if (signature_outcome[victim_idx] > 0)
        --signature_outcome[victim_idx];
    if (dead_block[set][way] < 3)
        ++dead_block[set][way];

    // --- Insertion policy ---
    if (streaming) {
        // Streaming detected: bypass (do not insert), or insert at RRPV=3
        rrpv[set][way] = 3;
    } else if (signature_outcome[sig_idx] >= 2) {
        // SHiP strong reuse: insert at MRU
        rrpv[set][way] = 0;
    } else {
        // SRRIP: insert at RRPV=2
        rrpv[set][way] = 2;
    }
    // Track signature for inserted block
    block_signature[set][way] = sig;
    // Reset dead-block counter on insertion
    dead_block[set][way] = 0;
}

// --- Print statistics ---
void PrintStats() {
    uint32_t strong_sig = 0;
    for (uint32_t i = 0; i < 2048; ++i)
        if (signature_outcome[i] >= 2) ++strong_sig;
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 32) ++streaming_sets;
    std::cout << "SHiP-Stream-DBI Policy\n";
    std::cout << "Strong reuse signatures: " << strong_sig << " / 2048\n";
    std::cout << "Streaming sets: " << streaming_sets << " / " << LLC_SETS << "\n";
}

// --- Heartbeat stats ---
void PrintStats_Heartbeat() {
    // Optional: print periodic streaming set count
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 32) ++streaming_sets;
    std::cout << "[Heartbeat] Streaming sets: " << streaming_sets << " / " << LLC_SETS << "\n";
}