#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-Lite: 4-bit PC signature per block, 2-bit outcome counter per entry ---
#define SHIP_SIG_BITS 4
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 16 entries
uint8_t ship_signature[LLC_SETS][LLC_WAYS];                // 4-bit signature per block
uint8_t ship_outcome_counter[LLC_SETS][SHIP_SIG_ENTRIES];  // 2-bit saturating counter per signature per set

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_outcome_counter, 1, sizeof(ship_outcome_counter)); // neutral start
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
    // Standard RRIP victim selection (evict block with RRPV==3)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
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

    // --- SHiP-Lite signature extraction ---
    uint8_t sig = (PC ^ (PC >> 4) ^ (paddr >> 8)) & ((1 << SHIP_SIG_BITS) - 1);

    // --- On hit, update outcome counter ---
    if (hit) {
        // Promote to MRU
        rrpv[set][way] = 0;
        // Increment outcome counter for signature (max 3)
        if (ship_outcome_counter[set][ship_signature[set][way]] < 3)
            ship_outcome_counter[set][ship_signature[set][way]]++;
    } else {
        // On miss/insert, assign current signature to block
        ship_signature[set][way] = sig;
        // Insertion depth selection
        uint8_t ins_rrpv = 2; // Default: medium reuse
        if (streaming_flag[set]) {
            // Streaming detected: always insert at LRU
            ins_rrpv = 3;
        } else {
            // Use outcome counter for signature to bias insertion
            uint8_t ctr = ship_outcome_counter[set][sig];
            if (ctr >= 2)
                ins_rrpv = 0; // High reuse: insert at MRU
            else if (ctr == 1)
                ins_rrpv = 2; // Neutral reuse: insert at mid
            else
                ins_rrpv = 3; // Low reuse: insert at LRU
        }
        rrpv[set][way] = ins_rrpv;

        // On eviction, decrement outcome counter for old block's signature
        uint8_t old_sig = ship_signature[set][way];
        if (ship_outcome_counter[set][old_sig] > 0)
            ship_outcome_counter[set][old_sig]--;
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    int high_reuse = 0, low_reuse = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (streaming_flag[s]) streaming_sets++;
        for (uint32_t sig = 0; sig < SHIP_SIG_ENTRIES; ++sig) {
            if (ship_outcome_counter[sig][sig] >= 2) high_reuse++;
            if (ship_outcome_counter[sig][sig] == 0) low_reuse++;
        }
    }
    std::cout << "SHiP-Lite-SA: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "SHiP-Lite-SA: High reuse signatures: " << high_reuse << std::endl;
    std::cout << "SHiP-Lite-SA: Low reuse signatures: " << low_reuse << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-Lite-SA: Streaming sets: " << streaming_sets << std::endl;
}