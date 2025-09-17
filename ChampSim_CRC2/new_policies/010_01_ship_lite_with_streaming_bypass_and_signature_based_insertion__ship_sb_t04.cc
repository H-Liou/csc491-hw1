#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-Lite Metadata ---
// Per-line: 6-bit signature, 2-bit RRPV
uint8_t rrpv[LLC_SETS][LLC_WAYS];           // 2 bits/line
uint8_t signature[LLC_SETS][LLC_WAYS];      // 6 bits/line

// Signature outcome table: 1024 entries, 2 bits each (shared global)
#define SIG_TABLE_SIZE 1024
uint8_t sig_table[SIG_TABLE_SIZE];          // 2 bits/entry

// --- Streaming detector: per-set, 1 bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];           // 1 bit/set
uint32_t last_addr[LLC_SETS];               // 32 bits/set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(signature, 0, sizeof(signature));
    memset(sig_table, 1, sizeof(sig_table)); // Start at weakly-dead (1)
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Utility: hash PC to 6-bit signature ---
inline uint8_t GetSignature(uint64_t PC) {
    // Simple hash: take lower 6 bits XOR upper 6 bits
    return ((PC ^ (PC >> 12)) & 0x3F);
}

// --- Utility: signature table index ---
inline uint16_t SigIndex(uint8_t sig) {
    // Map 6-bit signature to 10-bit table index (folded)
    return ((sig * 37) & (SIG_TABLE_SIZE - 1));
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
    // Streaming bypass: if detected, always evict LRU (RRPV==3)
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

    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);
    uint16_t idx = SigIndex(sig);

    // --- Update signature table on hit/miss ---
    if (hit) {
        // Promote RRPV to MRU
        rrpv[set][way] = 0;
        // Strengthen outcome counter (max 3)
        if (sig_table[idx] < 3) sig_table[idx]++;
    } else {
        // On fill: set line's signature
        signature[set][way] = sig;
        // Weaken outcome counter (min 0)
        if (sig_table[idx] > 0) sig_table[idx]--;
    }

    // --- Insertion policy ---
    uint8_t ins_rrpv = 2; // default to SRRIP insertion

    // Streaming bypass: never insert (set RRPV=3)
    if (streaming_flag[set]) {
        rrpv[set][way] = 3;
        return;
    }

    // SHiP insertion: if signature outcome counter is strong (>=2), insert MRU; else LRU
    if (sig_table[idx] >= 2)
        ins_rrpv = 0; // insert at MRU
    else if (sig_table[idx] == 1)
        ins_rrpv = 2; // mid
    else
        ins_rrpv = 3; // insert at LRU

    rrpv[set][way] = ins_rrpv;
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-SB: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // Print signature table histogram
    int strong = 0, weak = 0, dead = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_table[i] >= 2) strong++;
        else if (sig_table[i] == 1) weak++;
        else dead++;
    }
    std::cout << "SHiP-SB: Signature table: strong=" << strong << " weak=" << weak << " dead=" << dead << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-SB: Streaming sets: " << streaming_sets << std::endl;
}