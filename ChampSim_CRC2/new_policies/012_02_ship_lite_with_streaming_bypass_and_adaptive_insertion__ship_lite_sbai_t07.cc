#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata: 2 bits per line ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits/line

// --- SHiP-lite: 6-bit PC signature table, 2-bit outcome counters ---
#define SHIP_SIG_BITS 6
#define SHIP_ENTRIES 2048 // fits 6b index: 64 KiB total for 2b*2K + overhead

struct SHIPEntry {
    uint8_t reuse_ctr; // 2 bits
};

SHIPEntry ship_table[SHIP_ENTRIES];

// --- Store PC signature per line (6 bits) ---
uint8_t line_sig[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- Periodic decay counter for SHiP table ---
uint64_t access_counter = 0;
#define SHIP_DECAY_PERIOD 100000

// --- Helper: get 6-bit signature from PC ---
inline uint8_t GetSignature(uint64_t PC) {
    return (uint8_t)((PC >> 2) & ((1 << SHIP_SIG_BITS) - 1));
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(line_sig, 0, sizeof(line_sig));
    memset(ship_table, 0, sizeof(ship_table));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Victim selection: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming phase: bypass cache if monotonic access detected
    if (streaming_flag[set]) {
        // Prefer evicting block with RRPV=3 (LRU)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Else, increment RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
        // Recurse: always returns a block
        return GetVictimInSet(cpu, set, current_set, PC, paddr, type);
    }
    // Normal RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Replacement state update ---
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
    access_counter++;

    // --- Streaming detector update (per set) ---
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- SHiP-lite signature ---
    uint8_t sig = GetSignature(PC);
    line_sig[set][way] = sig;

    // --- SHiP outcome counter update ---
    if (hit) {
        if (ship_table[sig].reuse_ctr < 3)
            ship_table[sig].reuse_ctr++;
    } else {
        if (ship_table[sig].reuse_ctr > 0)
            ship_table[sig].reuse_ctr--;
    }

    // --- Periodic decay of SHiP table ---
    if (access_counter % SHIP_DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
            if (ship_table[i].reuse_ctr > 0)
                ship_table[i].reuse_ctr--;
    }

    // --- Adaptive insertion depth ---
    uint8_t ins_rrpv = 2; // Default: SRRIP insertion (RRPV=2)
    // If streaming detected, insert at distant RRPV (LRU)
    if (streaming_flag[set])
        ins_rrpv = 3;
    // If signature has low reuse, insert at LRU
    else if (ship_table[sig].reuse_ctr == 0)
        ins_rrpv = 3;
    // If signature has moderate reuse, insert at mid
    else if (ship_table[sig].reuse_ctr == 1)
        ins_rrpv = 2;
    // High reuse: insert at MRU
    else if (ship_table[sig].reuse_ctr >= 2)
        ins_rrpv = 0;

    // --- RRIP update ---
    if (hit)
        rrpv[set][way] = 0; // Promote to MRU
    else
        rrpv[set][way] = ins_rrpv;
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-Lite-SBAI: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;

    int high_reuse = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_table[i].reuse_ctr >= 2) high_reuse++;
    std::cout << "SHiP-Lite-SBAI: High-reuse signatures: " << high_reuse << " / " << SHIP_ENTRIES << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-Lite-SBAI: Streaming sets: " << streaming_sets << std::endl;
}