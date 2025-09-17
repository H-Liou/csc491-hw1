#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP bits: 2 per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: per-set, 32-entry table of 4-bit PC signatures, each with 2-bit reuse counter ---
#define SHIP_SIG_BITS 4
#define SHIP_TABLE_SIZE 32
uint16_t ship_sig_table[LLC_SETS][SHIP_TABLE_SIZE]; // 4-bit PC sig per entry
uint8_t ship_reuse_ctr[LLC_SETS][SHIP_TABLE_SIZE];  // 2-bit counter per entry

// --- Streaming detector: per-set, 2-bit saturating counter + last address ---
uint8_t streaming_ctr[LLC_SETS]; // 2-bit counter per set
uint64_t last_addr[LLC_SETS];    // last paddr per set

// --- Simple hash for signature index ---
inline uint32_t sig_index(uint64_t PC) {
    return (PC ^ (PC >> SHIP_SIG_BITS)) & (SHIP_TABLE_SIZE - 1);
}
inline uint16_t sig_value(uint64_t PC) {
    return (PC >> 2) & 0xF;
}

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All blocks distant
    memset(ship_sig_table, 0, sizeof(ship_sig_table));
    memset(ship_reuse_ctr, 0, sizeof(ship_reuse_ctr));
    memset(streaming_ctr, 0, sizeof(streaming_ctr));
    memset(last_addr, 0, sizeof(last_addr));
}

//--------------------------------------------
// Find victim in the set (RRIP)
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
            rrpv[set][way]++;
    }
    return 0; // Should not reach
}

//--------------------------------------------
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
    uint64_t prev_addr = last_addr[set];
    uint64_t delta = (prev_addr > 0) ? (paddr > prev_addr ? paddr - prev_addr : prev_addr - paddr) : 0;
    last_addr[set] = paddr;

    // If delta is small and monotonic (e.g., stride < 256), increment streaming counter
    if (prev_addr > 0 && delta > 0 && delta < 256)
        if (streaming_ctr[set] < 3) streaming_ctr[set]++;
    else
        if (streaming_ctr[set] > 0) streaming_ctr[set]--;

    bool is_streaming = (streaming_ctr[set] >= 2);

    // --- SHiP-lite index ---
    uint32_t sig_idx = sig_index(PC);
    uint16_t sig_val = sig_value(PC);

    // --- On hit: promote and learn reuse ---
    if (hit) {
        if (ship_sig_table[set][sig_idx] == sig_val) {
            if (ship_reuse_ctr[set][sig_idx] < 3)
                ship_reuse_ctr[set][sig_idx]++;
        } else {
            ship_sig_table[set][sig_idx] = sig_val;
            ship_reuse_ctr[set][sig_idx] = 1;
        }
        rrpv[set][way] = 0; // promote on hit
        return;
    }

    // --- On miss: insertion policy ---
    uint8_t reuse = (ship_sig_table[set][sig_idx] == sig_val) ? ship_reuse_ctr[set][sig_idx] : 0;

    if (is_streaming) {
        // Streaming detected: insert at RRPV=3 (LIP), or bypass if reuse==0
        if (reuse == 0)
            rrpv[set][way] = 3; // distant (effectively LIP/bypass)
        else
            rrpv[set][way] = 2; // intermediate if some reuse
    } else {
        // Not streaming: SHiP-lite guides insertion
        if (reuse >= 2)
            rrpv[set][way] = 0; // long retention
        else
            rrpv[set][way] = 3; // LIP: insert distant, promote only on hit
    }

    // --- Update SHiP-lite table ---
    ship_sig_table[set][sig_idx] = sig_val;
    ship_reuse_ctr[set][sig_idx] = (reuse > 0) ? (reuse - 1) : 0; // slight decay on miss
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Streaming-Aware SHiP-Lite + LIP Hybrid: Final statistics." << std::endl;
    // Optionally print streaming counters for debug
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (streaming_ctr[i] >= 2) streaming_sets++;
    std::cout << "Sets detected as streaming: " << streaming_sets << " / " << LLC_SETS << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (streaming_ctr[i] >= 2) streaming_sets++;
    std::cout << "[Heartbeat] Streaming sets: " << streaming_sets << std::endl;
}