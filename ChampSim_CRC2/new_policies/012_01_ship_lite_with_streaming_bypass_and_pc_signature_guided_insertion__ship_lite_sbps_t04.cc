#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
// PC signatures: 6 bits per line
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 6 bits/line

// SHiP table: 1024 entries, 2 bits per signature
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_ctr[SHIP_TABLE_SIZE]; // 2 bits per entry

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- RRIP state: 2 bits per line ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Initialize to neutral
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
    // Streaming phase: bypass cache for blocks with dead signature
    uint8_t sig = (uint8_t)(PC ^ (paddr >> 6)) & ((1 << SHIP_SIG_BITS) - 1);
    if (streaming_flag[set] && ship_ctr[sig] == 0) {
        // Find block with max RRPV (LRU)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // If none, increment all RRPVs and retry
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        return 0;
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
    // --- Streaming detector update (per set) ---
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- SHiP signature extraction ---
    uint8_t sig = (uint8_t)(PC ^ (paddr >> 6)) & ((1 << SHIP_SIG_BITS) - 1);

    // --- On hit: update SHiP table and promote ---
    if (hit) {
        if (ship_ctr[sig] < 3)
            ship_ctr[sig]++;
        rrpv[set][way] = 0; // Promote to MRU
    } else {
        // On miss: update SHiP table for victim
        uint8_t victim_sig = pc_sig[set][way];
        if (ship_ctr[victim_sig] > 0)
            ship_ctr[victim_sig]--;
        // Assign new signature to incoming line
        pc_sig[set][way] = sig;

        // --- Insertion policy: guided by SHiP table ---
        // If streaming and dead signature, insert at LRU (RRPV=3)
        uint8_t ins_rrpv = 2;
        if (streaming_flag[set] && ship_ctr[sig] == 0)
            ins_rrpv = 3;
        else if (ship_ctr[sig] == 0)
            ins_rrpv = 3; // Dead signature: LRU
        else if (ship_ctr[sig] == 3)
            ins_rrpv = 0; // Hot signature: MRU
        else
            ins_rrpv = 2; // Neutral

        rrpv[set][way] = ins_rrpv;
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-Lite-SBPS: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;

    int hot_sigs = 0, dead_sigs = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_ctr[i] == 3) hot_sigs++;
        if (ship_ctr[i] == 0) dead_sigs++;
    }
    std::cout << "SHiP-Lite-SBPS: Hot signatures: " << hot_sigs << " / " << SHIP_TABLE_SIZE << std::endl;
    std::cout << "SHiP-Lite-SBPS: Dead signatures: " << dead_sigs << " / " << SHIP_TABLE_SIZE << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-Lite-SBPS: Streaming sets: " << streaming_sets << std::endl;
}