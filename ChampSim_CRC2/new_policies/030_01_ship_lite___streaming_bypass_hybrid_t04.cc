#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-Lite Predictor ---
// 6-bit signature table: 64 entries per set, 2 bits per entry
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64
uint8_t ship_table[LLC_SETS][SHIP_SIG_ENTRIES]; // 2 bits per entry

// --- RRPV state ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector: per-set, 2-bit counter, last address ---
uint64_t last_addr[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set
#define STREAM_THRESHOLD 3

// --- Per-block signature ---
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_table, 1, sizeof(ship_table)); // neutral initial value
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(block_sig, 0, sizeof(block_sig));
}

// --- Streaming detector update ---
inline void update_streaming(uint32_t set, uint64_t paddr) {
    uint64_t last = last_addr[set];
    uint64_t delta = (last == 0) ? 0 : (paddr > last ? paddr - last : last - paddr);
    // Detect monotonic stride: delta == block size (64B), or small stride
    if (last != 0 && (delta == 64 || delta == 128)) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_addr[set] = paddr;
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
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
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
    // --- Streaming detector update ---
    update_streaming(set, paddr);

    // --- SHiP-Lite signature ---
    uint8_t sig = champsim_crc2(PC, set) & (SHIP_SIG_ENTRIES - 1);

    // --- Streaming detection ---
    bool streaming = (stream_ctr[set] >= STREAM_THRESHOLD);

    // --- SHiP outcome update ---
    if (hit) {
        // On hit, promote block and increment SHiP outcome
        rrpv[set][way] = 0;
        if (ship_table[set][block_sig[set][way]] < 3)
            ship_table[set][block_sig[set][way]]++;
    } else {
        // On miss, update SHiP outcome for victim block (dead-on-arrival)
        if (ship_table[set][block_sig[set][way]] > 0)
            ship_table[set][block_sig[set][way]]--;
        // Insert new block
        block_sig[set][way] = sig;

        // --- Insertion depth policy ---
        uint8_t ins_rrpv = 2; // default SRRIP
        if (ship_table[set][sig] == 0) {
            // If signature has poor history, insert at distant RRPV=3
            ins_rrpv = 3;
        }
        // If streaming detected and signature is poor, bypass (do not cache)
        if (streaming && ship_table[set][sig] == 0) {
            // Bypass: mark line as always RRPV=3, so it is replaced immediately
            rrpv[set][way] = 3;
            return;
        }
        rrpv[set][way] = ins_rrpv;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= STREAM_THRESHOLD)
            streaming_sets++;
    std::cout << "Sets with streaming detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    // Print SHiP table summary
    uint32_t reused = 0, dead = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
            if (ship_table[s][i] >= 2) reused++;
            else if (ship_table[s][i] == 0) dead++;
    std::cout << "SHiP sigs: reused=" << reused << " dead=" << dead << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and SHiP table summary
}