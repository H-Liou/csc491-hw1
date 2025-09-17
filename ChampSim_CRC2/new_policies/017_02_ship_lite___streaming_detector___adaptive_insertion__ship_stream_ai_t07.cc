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

// --- RRIP Metadata ---
// 2-bit RRPV per block
static uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming Detector ---
// 2-bit streaming counter per set
static uint8_t stream_ctr[LLC_SETS];

// Last inserted address per set (for monotonic delta detection)
static uint64_t last_addr[LLC_SETS];

// Helper: hash PC to 6-bit signature
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Helper: hash signature to outcome table index (11 bits)
inline uint16_t SigIdx(uint8_t sig) {
    return (sig ^ (sig << 3)) & 0x7FF; // 2048 entries
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(block_signature, 0, sizeof(block_signature));
    memset(signature_outcome, 1, sizeof(signature_outcome)); // weak reuse by default
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Find victim: RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection: look for RRPV==3
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
    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);
    uint16_t sig_idx = SigIdx(sig);

    // --- Streaming Detection ---
    // Detect near-monotonic access pattern (streaming if address increases/decreases by cache line size)
    uint64_t stride = 64; // Assume 64B cache line
    if (last_addr[set] != 0) {
        int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
        if (delta == stride || delta == -stride) {
            if (stream_ctr[set] < 3) ++stream_ctr[set];
        } else {
            if (stream_ctr[set] > 0) --stream_ctr[set];
        }
    }
    last_addr[set] = paddr;

    // --- On hit: promote to MRU, update outcome counter
    if (hit) {
        rrpv[set][way] = 0;
        if (signature_outcome[sig_idx] < 3)
            ++signature_outcome[sig_idx];
        return;
    }

    // --- On miss: update outcome counter for victim block
    uint8_t victim_sig = block_signature[set][way];
    uint16_t victim_idx = SigIdx(victim_sig);
    if (signature_outcome[victim_idx] > 0)
        --signature_outcome[victim_idx];

    // --- Adaptive Insertion ---
    // If streaming detected (stream_ctr[set] >= 2), bypass or insert at distant RRPV
    if (stream_ctr[set] >= 2) {
        // Streaming mode: insert at RRPV=3 (LRU), and bypass with 15/16 probability
        static uint32_t streamp = 0;
        if ((streamp++ & 0xF) != 0) {
            // Bypass: do nothing, block not inserted (simulate by setting RRPV=3 and empty signature)
            rrpv[set][way] = 3;
            block_signature[set][way] = 0;
            return;
        }
        // Rarely keep a line in streaming sets
        rrpv[set][way] = 3;
    } else {
        // Non-streaming: use SHiP outcome for insertion depth
        if (signature_outcome[sig_idx] >= 2) {
            rrpv[set][way] = 0; // MRU
        } else {
            rrpv[set][way] = 2; // Intermediate
        }
    }

    // Track signature for inserted block
    block_signature[set][way] = sig;
}

// --- Print statistics ---
void PrintStats() {
    uint32_t strong_sig = 0;
    for (uint32_t i = 0; i < 2048; ++i)
        if (signature_outcome[i] >= 2) ++strong_sig;
    uint32_t stream_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (stream_ctr[i] >= 2) ++stream_sets;
    std::cout << "SHiP-Stream-AI Policy\n";
    std::cout << "Strong reuse signatures: " << strong_sig << " / 2048\n";
    std::cout << "Streaming sets (active): " << stream_sets << " / " << LLC_SETS << "\n";
}

// --- Heartbeat stats ---
void PrintStats_Heartbeat() {
    // Optionally print periodic streaming set count
}