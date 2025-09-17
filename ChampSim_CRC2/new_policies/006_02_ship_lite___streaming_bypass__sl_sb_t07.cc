#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHIP-Lite metadata ---
#define SIG_BITS 6                               // 6 bits per signature
#define SIG_TABLE_SIZE (LLC_SETS * 4)            // 4 entries/set
uint8_t sig_table[LLC_SETS][4];                  // 6-bit PC signatures
uint8_t sig_outcome[LLC_SETS][4];                // 2-bit saturating counters

// --- Streaming detector: 2-bit per set ---
uint8_t stream_ctr[LLC_SETS];                    // 2 bits/set
uint64_t last_addr[LLC_SETS];                    // For stride detection

// --- RRIP ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];                // 2 bits/line

// --- Initialization ---
void InitReplacementState() {
    memset(sig_table, 0, sizeof(sig_table));
    memset(sig_outcome, 1, sizeof(sig_outcome));   // Neutral start
    memset(rrpv, 3, sizeof(rrpv));                 // LRU
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Helper: Compute 6-bit PC signature ---
inline uint8_t GetPCSignature(uint64_t PC) {
    return (champsim_crc2(PC, 0) ^ (PC >> 2)) & 0x3F;
}

// --- Helper: Find/Allocate signature entry in set ---
int FindSigEntry(uint32_t set, uint8_t sig) {
    for (int i = 0; i < 4; ++i)
        if (sig_table[set][i] == sig)
            return i;
    return -1;
}
int AllocSigEntry(uint32_t set, uint8_t sig) {
    // Find empty slot or replace LRU (round-robin)
    static uint8_t rr_ptr[LLC_SETS] = {0};
    int idx = FindSigEntry(set, sig);
    if (idx >= 0) return idx;
    idx = rr_ptr[set];
    sig_table[set][idx] = sig;
    sig_outcome[set][idx] = 1; // neutral
    rr_ptr[set] = (rr_ptr[set] + 1) & 0x3;
    return idx;
}

// --- Streaming detector: Update per-set stride ---
bool IsStreaming(uint32_t set, uint64_t paddr) {
    uint64_t stride = paddr - last_addr[set];
    last_addr[set] = paddr;
    // Accept stride in [64, 4096] (typical cache line stride)
    if (stride >= 64 && stride <= 4096) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    // Streaming if counter is saturated (>=3)
    return stream_ctr[set] >= 3;
}

// --- Victim selection: Standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: return -1 to indicate bypass
    if (IsStreaming(set, paddr))
        return UINT32_MAX; // special value: bypass

    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
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
    // Streaming: if bypassed, nothing to update
    if (IsStreaming(set, paddr) && way == UINT32_MAX)
        return;

    // Get PC signature and find/alloc entry
    uint8_t sig = GetPCSignature(PC);
    int sig_idx = AllocSigEntry(set, sig);

    // On hit: promote to MRU, increment outcome
    if (hit) {
        rrpv[set][way] = 0;
        if (sig_outcome[set][sig_idx] < 3)
            sig_outcome[set][sig_idx]++;
    } else {
        // On fill: use SHIP outcome to choose insertion depth
        if (sig_outcome[set][sig_idx] >= 2)
            rrpv[set][way] = 0; // MRU insertion
        else
            rrpv[set][way] = 2; // Distant

        // On fill, decay signature counter slightly (to adapt)
        if (sig_outcome[set][sig_idx] > 0)
            sig_outcome[set][sig_idx]--;
    }

    // On eviction: if block was not reused, decrement outcome
    if (!hit && victim_addr) {
        if (sig_outcome[set][sig_idx] > 0)
            sig_outcome[set][sig_idx]--;
    }
}

// --- Statistics ---
void PrintStats() {
    int stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 3)
            stream_sets++;
    std::cout << "SL-SB: Streaming sets: " << stream_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    int stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 3)
            stream_sets++;
    std::cout << "SL-SB: Streaming sets: " << stream_sets << std::endl;
}