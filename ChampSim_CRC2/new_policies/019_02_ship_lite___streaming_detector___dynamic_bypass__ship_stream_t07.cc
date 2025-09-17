#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signature, 2-bit reuse counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating reuse counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: 2-bit per-set stride counter, 1-bit streaming flag ---
uint8_t stride_count[LLC_SETS];     // Counts monotonic fills (0-3)
uint64_t last_addr[LLC_SETS];       // Last filled address per set
uint8_t is_streaming[LLC_SETS];     // Flag: set is streaming

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant
    memset(stride_count, 0, sizeof(stride_count));
    memset(last_addr, 0, sizeof(last_addr));
    memset(is_streaming, 0, sizeof(is_streaming));
}

// --- Find victim: standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
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
    // --- SHiP-lite signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- Streaming detector logic ---
    // Detect monotonic progress: if new fill addr > last_addr, increment stride counter
    if (!hit) {
        if (last_addr[set] == 0) {
            last_addr[set] = paddr;
            stride_count[set] = 0;
        } else {
            if (paddr > last_addr[set]) {
                if (stride_count[set] < 3) stride_count[set]++;
            } else {
                if (stride_count[set] > 0) stride_count[set]--;
            }
            last_addr[set] = paddr;
        }
        // Streaming if stride_count saturates
        is_streaming[set] = (stride_count[set] >= 3) ? 1 : 0;
    }

    // --- On hit: update SHiP-lite predictor, set RRPV=0 ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++; // mark as reused
        rrpv[set][way] = 0;
        return;
    }

    // --- Decide insertion policy ---
    uint8_t ins_rrpv = 3; // default distant

    if (is_streaming[set]) {
        // Streaming detected: bypass (do not insert, if possible)
        // Champsim interface expects block to be inserted; use RRPV=3 to evict soon
        ins_rrpv = 3;
    } else if (ship_table[sig] >= 2) {
        // SHiP-lite: PC signature reused, insert at MRU
        ins_rrpv = 0;
    } else {
        ins_rrpv = 2; // default SRRIP insertion
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP-lite predictor for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ship_table[victim_sig] > 0) ship_table[victim_sig]--; // decay if evicted without reuse
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Stream: Final statistics." << std::endl;
    uint32_t reused_cnt = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i] >= 2) reused_cnt++;
    std::cout << "SHiP-lite predictor: " << reused_cnt << " signatures predicted reused." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (is_streaming[i]) streaming_sets++;
    std::cout << "Streaming sets detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and reuse histogram
}