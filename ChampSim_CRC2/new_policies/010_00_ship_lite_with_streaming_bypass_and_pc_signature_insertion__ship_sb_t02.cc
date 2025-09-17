#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
// Per-line: 5-bit PC signature
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 5 bits/line

// Global: 1024-entry, 2-bit outcome counters
#define SIG_TABLE_SIZE 1024
uint8_t sig_table[SIG_TABLE_SIZE]; // 2 bits/entry

// --- Streaming detector: per-set, 1 bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];         // 1 bit/set: 1 if streaming detected
uint32_t last_addr[LLC_SETS];             // 32 bits/set: last block address

// --- RRPV bits ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];         // 2 bits/line: RRIP value

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(sig_table, 1, sizeof(sig_table)); // Start with weak reuse
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Victim selection: standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if streaming detected, always evict LRU (RRPV==3)
    if (streaming_flag[set]) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment RRPVs if none found
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
    }

    // Normal SRRIP victim selection
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
    // --- Streaming detector update ---
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- SHiP-lite: signature extraction ---
    uint16_t sig = (PC ^ (PC >> 5)) & 0x1F; // 5-bit signature
    uint16_t sig_idx = sig; // 0..31, but use more bits for global table
    // For global table, use more PC bits for diversity
    uint16_t global_sig = (PC ^ (PC >> 10) ^ (PC >> 5)) & (SIG_TABLE_SIZE-1);

    // --- On hit: update outcome counter and promote ---
    if (hit) {
        rrpv[set][way] = 0; // promote to MRU
        // Update outcome counter (max 3)
        if (sig_table[global_sig] < 3)
            sig_table[global_sig]++;
    } else {
        // On fill: assign signature to line
        pc_sig[set][way] = sig;
        // Streaming bypass: if streaming detected, insert at LRU
        if (streaming_flag[set]) {
            rrpv[set][way] = 3;
        } else {
            // Use outcome counter to bias insertion depth
            uint8_t ctr = sig_table[global_sig];
            // If counter is high (>=2), insert at RRPV=0 (MRU); else at RRPV=3 (LRU)
            rrpv[set][way] = (ctr >= 2) ? 0 : 3;
        }
    }

    // --- On eviction: update outcome counter for the signature of the evicted line ---
    // Find the signature of the victim block
    uint8_t victim_sig = pc_sig[set][way];
    uint16_t victim_global_sig = (victim_sig ^ (victim_sig << 2)) & (SIG_TABLE_SIZE-1);
    // If block was not reused (i.e., not a hit), decrement counter
    if (!hit) {
        if (sig_table[victim_global_sig] > 0)
            sig_table[victim_global_sig]--;
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-SB: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;

    int high_reuse = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_table[i] >= 2) high_reuse++;
    std::cout << "SHiP-SB: High-reuse signatures: " << high_reuse << " / " << SIG_TABLE_SIZE << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-SB: Streaming sets: " << streaming_sets << std::endl;
}