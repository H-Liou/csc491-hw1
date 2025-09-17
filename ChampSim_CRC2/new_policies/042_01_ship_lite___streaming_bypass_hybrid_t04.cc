#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit signature per block, 2048-entry table ---
uint8_t block_sig[LLC_SETS][LLC_WAYS];       // 6 bits per block
uint8_t ship_ctr[2048];                      // 2 bits per signature

// --- RRIP state ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];            // 2 bits per block

// --- Streaming detector: 1 byte per set ---
uint8_t stream_window[LLC_SETS];             // tracks monotonic delta count (0–255)
uint64_t last_addr[LLC_SETS];                // last address per set

// Helper: hash PC to 6 bits
inline uint8_t sig_hash(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Helper: hash signature to ship_ctr index
inline uint16_t sig_index(uint8_t sig) {
    // Use signature as index (0–63), expand by folding set for better distribution
    return sig | ((sig << 5) & 0x7C0);
}

// Initialize replacement state
void InitReplacementState() {
    memset(block_sig, 0, sizeof(block_sig));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // neutral reuse
    memset(rrpv, 2, sizeof(rrpv));         // distant
    memset(stream_window, 0, sizeof(stream_window));
    memset(last_addr, 0, sizeof(last_addr));
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
    // RRIP victim selection
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
    uint64_t last = last_addr[set];
    uint8_t monotonic = 0;
    if (last != 0) {
        int64_t delta = (int64_t)paddr - (int64_t)last;
        if (delta == 64 || delta == -64) // typical cache line stride
            monotonic = 1;
    }
    last_addr[set] = paddr;
    // Update window: saturating count of monotonic accesses
    if (monotonic && stream_window[set] < 255)
        stream_window[set]++;
    else if (!monotonic && stream_window[set] > 0)
        stream_window[set]--;

    // --- SHiP-lite signature ---
    uint8_t sig = sig_hash(PC);
    uint16_t idx = sig_index(sig);

    // --- On hit: reward signature ---
    if (hit) {
        rrpv[set][way] = 0; // protect reused block
        if (ship_ctr[idx] < 3) ship_ctr[idx]++;
    }
    // --- On miss: penalize signature ---
    else {
        if (ship_ctr[idx] > 0) ship_ctr[idx]--;
    }

    // --- Streaming bypass logic ---
    bool bypass = (stream_window[set] > 200); // >80% monotonic in recent window

    // --- On fill (miss): decide insertion or bypass ---
    if (!hit) {
        block_sig[set][way] = sig;
        if (bypass) {
            // Do not insert: mark block invalid (simulate bypass)
            rrpv[set][way] = 3;
            current_set[way].valid = 0; // Champsim: would skip fill
        } else {
            // SHiP counter controls insertion depth
            if (ship_ctr[idx] == 3)
                rrpv[set][way] = 0; // high reuse, insert as MRU
            else if (ship_ctr[idx] == 2)
                rrpv[set][way] = 1; // moderate reuse
            else
                rrpv[set][way] = 2; // low reuse, insert as distant
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int mru_blocks = 0, distant_blocks = 0, bypassed = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) mru_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (!rrpv[set][way]) bypassed += !rrpv[set][way];
        }
    }
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid Policy" << std::endl;
    std::cout << "MRU blocks: " << mru_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    // Print streaming sets
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_window[set] > 200) streaming_sets++;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_window[set] > 200) streaming_sets++;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}