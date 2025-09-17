#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite Metadata ---
#define SIG_BITS 6
#define SHIP_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming Detector Metadata ---
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN]; // last 4 addresses per set
uint8_t stream_hist_ptr[LLC_SETS]; // circular pointer per set

// --- Streaming Detector Thresholds ---
#define STREAM_DETECT_COUNT 3 // at least 3 matching deltas

// --- Phase Counter (per set, 2 bits) ---
uint8_t phase_ctr[LLC_SETS]; // 2 bits per set

// --- Dead-on-arrival counter (per set, 2 bits) ---
uint8_t doa_ctr[LLC_SETS]; // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start at weak reuse
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    memset(phase_ctr, 0, sizeof(phase_ctr));
    memset(doa_ctr, 0, sizeof(doa_ctr));
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// --- Streaming Detector: returns true if streaming detected ---
bool is_streaming(uint32_t set, uint64_t paddr) {
    uint8_t ptr = stream_hist_ptr[set];
    stream_addr_hist[set][ptr] = paddr;
    stream_hist_ptr[set] = (ptr + 1) % STREAM_HIST_LEN;
    if (ptr < STREAM_HIST_LEN - 1)
        return false; // not enough history yet
    int64_t ref_delta = (int64_t)stream_addr_hist[set][1] - (int64_t)stream_addr_hist[set][0];
    int match = 0;
    for (int i = 2; i < STREAM_HIST_LEN; ++i) {
        int64_t d = (int64_t)stream_addr_hist[set][i] - (int64_t)stream_addr_hist[set][i-1];
        if (d == ref_delta) match++;
    }
    return (match >= STREAM_DETECT_COUNT - 1);
}

// --- Find victim in the set ---
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

    // RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
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
    uint8_t sig = get_signature(PC);

    // Streaming detection
    bool streaming = is_streaming(set, paddr);

    // --- Streaming bypass: if streaming detected, do not insert ---
    if (streaming) {
        rrpv[set][way] = 3; // Mark as LRU (effectively bypass)
        ship_signature[set][way] = sig;
        ship_ctr[set][way] = 0; // Reset reuse
        return;
    }

    // On hit: promote block, increment reuse counter
    if (hit) {
        rrpv[set][way] = 0; // MRU
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        doa_ctr[set] = 0; // Reset dead-on-arrival counter
        return;
    }

    // --- SHiP bias: if strong reuse, insert at MRU ---
    uint8_t insertion_rrpv = 3; // Default: insert at LRU (LIP)
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0; // Insert at MRU

    // --- Phase-adaptive insertion: if set has frequent dead-on-arrival, switch to BIP ---
    if (phase_ctr[set] >= 2) {
        // BIP: insert at MRU with 1/32 probability, else at LRU
        insertion_rrpv = ((rand() % 32) == 0) ? 0 : 3;
    }

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // Weak reuse

    // --- Dead-on-arrival detection: if block inserted at LRU and evicted without hit, increment doa_ctr ---
    if (!hit && insertion_rrpv == 3) {
        if (doa_ctr[set] < 3) doa_ctr[set]++;
        if (doa_ctr[set] >= 2 && phase_ctr[set] < 3) phase_ctr[set]++;
    } else {
        if (doa_ctr[set] > 0) doa_ctr[set]--;
        if (phase_ctr[set] > 0) phase_ctr[set]--;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0;
    int streaming_sets = 0, phase_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
        if (phase_ctr[s] >= 2) phase_sets++;
    }
    std::cout << "SHiP-LIP-SBPA Policy: SHiP-lite + LIP/BIP phase-adaptive + Streaming Bypass" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Sets in phase-adaptive mode: " << phase_sets << "/" << LLC_SETS << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0;
    int phase_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
        if (phase_ctr[s] >= 2) phase_sets++;
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks
              << ", Sets in phase-adaptive mode: " << phase_sets << std::endl;
}