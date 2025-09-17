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

// --- LIP: always insert at LRU (RRPV=3), promote on hit ---
const uint8_t LIP_INSERT_RRPV = 3;
const uint8_t MRU_RRPV = 0;

// --- Streaming detector: per-set stride history, 2-bit counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2-bit saturating counter

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, LIP_INSERT_RRPV, sizeof(rrpv));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
}

// --- Find victim: standard SRRIP (prefer RRPV==3) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
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

    // --- Streaming detector: update stride and counter ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0) {
        if (delta == last_delta[set]) {
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- On hit: promote to MRU, update SHiP ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = MRU_RRPV;
        return;
    }

    // --- Streaming bypass: if stream_ctr saturated, bypass insertion ---
    if (stream_ctr[set] == 3) {
        // Do not insert: mark block as invalid (simulate bypass)
        rrpv[set][way] = 3; // Will be replaced immediately
        block_sig[set][way] = sig;
        // On eviction, update SHiP predictor for victim block
        uint8_t victim_sig = block_sig[set][way];
        if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;
        return;
    }

    // --- SHiP-guided insertion: MRU if predicted reused, else LIP ---
    uint8_t ins_rrpv = LIP_INSERT_RRPV;
    if (ship_table[sig] >= 2)
        ins_rrpv = MRU_RRPV; // Predicted reused: insert at MRU
    // else: LIP (insert at LRU)

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // On eviction, update SHiP predictor for victim block
    uint8_t victim_sig = block_sig[set][way];
    if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-LIP Hybrid + Streaming Bypass: Final statistics." << std::endl;
    uint32_t reused_cnt = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i] >= 2) reused_cnt++;
    std::cout << "SHiP-lite predictor: " << reused_cnt << " signatures predicted reused." << std::endl;

    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] == 3)
            streaming_sets++;
    std::cout << "Sets detected streaming: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count
}