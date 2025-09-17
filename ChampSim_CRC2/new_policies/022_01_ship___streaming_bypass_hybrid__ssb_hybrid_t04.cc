#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signature, 2-bit counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: 2-bit per set, last address per set ---
uint8_t stream_ctr[LLC_SETS]; // 2-bit saturating counter per set
uint64_t last_addr[LLC_SETS]; // last filled address per set
uint64_t last_delta[LLC_SETS]; // last observed delta per set

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
}

// --- Find victim: SRRIP (victim with RRPV==3) ---
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
    // --- SHiP-lite signature ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- Streaming detector: update on fill (miss only) ---
    if (!hit) {
        uint64_t delta = (last_addr[set] == 0) ? 0 : (paddr - last_addr[set]);
        if (last_addr[set] != 0 && delta == last_delta[set] && delta != 0) {
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
        last_delta[set] = delta;
        last_addr[set] = paddr;
    }

    // --- On hit: update SHiP predictor and RRPV ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = 0;
        return;
    }

    // --- Decide insertion policy: SHiP-lite + streaming bypass ---
    uint8_t ins_rrpv = 3; // default distant

    // 1. Streaming sets: bypass or distant insert if streaming detected
    if (stream_ctr[set] >= 2) {
        // Streaming detected: insert at RRPV=3 (distant), i.e. likely to be replaced soon
        ins_rrpv = 3;
    }
    // 2. SHiP-lite: MRU insert if signature is reused
    else if (ship_table[sig] >= 2) {
        ins_rrpv = 0;
    }
    // 3. Otherwise, SRRIP: insert at RRPV=2
    else {
        ins_rrpv = 2;
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP predictor for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP + Streaming Bypass Hybrid: Final statistics." << std::endl;
    uint32_t reused_cnt = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i] >= 2) reused_cnt++;
    std::cout << "SHiP-lite predictor: " << reused_cnt << " signatures predicted reused." << std::endl;

    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and reuse histogram
}