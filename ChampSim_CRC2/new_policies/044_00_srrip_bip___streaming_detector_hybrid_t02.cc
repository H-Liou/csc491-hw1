#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2-bit per block

// --- Set-dueling for SRRIP vs BIP ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_srrip[LLC_SETS]; // 1 if SRRIP leader
uint8_t is_leader_bip[LLC_SETS];   // 1 if BIP leader

// --- Streaming detector: per-set address delta history ---
#define STREAM_WINDOW 4
uint64_t last_addr[LLC_SETS];              // Last accessed address per set
int8_t delta_hist[LLC_SETS][STREAM_WINDOW]; // Last STREAM_WINDOW address deltas per set
uint8_t stream_score[LLC_SETS];            // Streaming confidence per set (0-3)

// --- BIP probability ---
#define BIP_PROB 32 // Insert MRU every 1/BIP_PROB

// --- Access counter for stats ---
uint64_t access_count = 0;

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way] = 2;
        is_leader_srrip[set] = 0;
        is_leader_bip[set] = 0;
        last_addr[set] = 0;
        stream_score[set] = 0;
        for (int i = 0; i < STREAM_WINDOW; ++i)
            delta_hist[set][i] = 0;
    }
    // First DUEL_LEADER_SETS sets are SRRIP-leader, next DUEL_LEADER_SETS are BIP-leader
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_srrip[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_bip[i] = 1;
    psel = (1 << (PSEL_BITS-1));
    access_count = 0;
}

// Streaming detector: update per-set delta history and score
void UpdateStreamingScore(uint32_t set, uint64_t paddr) {
    int8_t delta = (int8_t)((paddr >> 6) - (last_addr[set] >> 6)); // block-granular
    last_addr[set] = paddr;
    // Shift history
    for (int i = STREAM_WINDOW-1; i > 0; --i)
        delta_hist[set][i] = delta_hist[set][i-1];
    delta_hist[set][0] = delta;
    // Streaming detection: if all recent deltas are equal and nonzero, boost score
    bool monotonic = true;
    int8_t ref = delta_hist[set][0];
    if (ref == 0) monotonic = false;
    for (int i = 1; i < STREAM_WINDOW; ++i)
        if (delta_hist[set][i] != ref)
            monotonic = false;
    if (monotonic && ref != 0) {
        if (stream_score[set] < 3) stream_score[set]++;
    } else {
        if (stream_score[set] > 0) stream_score[set]--;
    }
}

// Find victim in the set (standard RRIP)
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
    access_count++;
    UpdateStreamingScore(set, paddr);

    // Streaming phase: if stream_score high, insert at distant RRPV or bypass
    if (stream_score[set] >= 2) {
        rrpv[set][way] = 3; // Bypass (insert at LRU)
        // For leader sets, update PSEL if miss
        if (is_leader_bip[set] && !hit)
            if (psel < ((1<<PSEL_BITS)-1)) psel++;
        return;
    }

    // Non-streaming: choose between SRRIP and BIP
    bool use_srrip;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_bip[set])
        use_srrip = false;
    else
        use_srrip = (psel < (1 << (PSEL_BITS-1)));

    if (use_srrip) {
        // SRRIP: insert at distant RRPV (2)
        rrpv[set][way] = 2;
        if (is_leader_srrip[set] && !hit)
            if (psel > 0) psel--;
    } else {
        // BIP: insert at LRU (2), but every BIP_PROB-th insertion, insert at MRU (0)
        if (access_count % BIP_PROB == 0)
            rrpv[set][way] = 0;
        else
            rrpv[set][way] = 2;
        if (is_leader_bip[set] && !hit)
            if (psel < ((1<<PSEL_BITS)-1)) psel++;
    }

    // On hit, always promote to MRU
    if (hit)
        rrpv[set][way] = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) stream_sets++;
    std::cout << "SRRIP-BIP+Stream: Streaming sets: " << stream_sets << " / " << LLC_SETS << std::endl;
    std::cout << "SRRIP-BIP+Stream: PSEL: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) stream_sets++;
    std::cout << "SRRIP-BIP+Stream: Streaming sets: " << stream_sets << std::endl;
    std::cout << "SRRIP-BIP+Stream: PSEL: " << psel << std::endl;
}