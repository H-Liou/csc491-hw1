#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Signature-based dead-block predictor ---
// Per-block: 5-bit signature, 1-bit deadness
#define SIG_BITS 5
#define SIG_TABLE_SIZE 32
uint8_t block_sig[LLC_SETS][LLC_WAYS];      // Per-block signature
uint8_t block_dead[LLC_SETS][LLC_WAYS];     // 1 if not reused during residency

// Global dead-block predictor table: 2-bit saturating counter per signature
uint8_t sig_reuse[SIG_TABLE_SIZE];          // 2: hot, 0–1: cold

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            block_dead[set][way] = 1;
        }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_reuse[i] = 1;
}

// Find victim in the set (SRRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
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
    // --- Signature extraction ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x1F)) & ((1 << SIG_BITS) - 1);

    if (hit) {
        // Block was reused: reward signature, set to MRU, mark as not dead
        if (sig_reuse[block_sig[set][way]] < 3)
            sig_reuse[block_sig[set][way]]++;
        rrpv[set][way] = 0;
        block_dead[set][way] = 0;
    } else {
        // If evicted block was never reused, decay its signature's counter
        if (block_dead[set][way]) {
            uint8_t old_sig = block_sig[set][way];
            if (sig_reuse[old_sig] > 0)
                sig_reuse[old_sig]--;
        }
        // Insert new block: record signature, mark as dead, set RRPV
        block_sig[set][way] = sig;
        block_dead[set][way] = 1;
        // Hot signature: insert at MRU; cold: distant
        if (sig_reuse[sig] >= 2)
            rrpv[set][way] = 0;
        else
            rrpv[set][way] = 2;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_sigs = 0, cold_sigs = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_reuse[i] >= 2) hot_sigs++;
        else cold_sigs++;
    std::cout << "SRRIP-GDBP: Hot signatures: " << hot_sigs
              << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SRRIP-GDBP: Cold signatures: " << cold_sigs << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int hot_sigs = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_reuse[i] >= 2) hot_sigs++;
    std::cout << "SRRIP-GDBP: Hot signature count: " << hot_sigs << std::endl;
}