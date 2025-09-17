#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP: 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter table (4096 entries)
#define SIG_BITS 6
#define SIG_TABLE_SIZE 4096
uint8_t ship_ctr[SIG_TABLE_SIZE]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- Dead-block predictor: 2-bit counter per block, periodic decay
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector: last address per set, last delta, streaming flag
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t is_streaming[LLC_SETS]; // 1 = streaming, 0 = not

// --- DRRIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
uint16_t psel = 512; // 10 bits, mid value
uint8_t is_leader_srrip[LLC_SETS]; // 1 if SRRIP leader, 2 if BRRIP leader, 0 otherwise

// --- Dead-block decay heartbeat
uint64_t global_access_counter = 0;
#define DEAD_DECAY_PERIOD 4096

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // neutral initial value
    memset(block_sig, 0, sizeof(block_sig));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(is_streaming, 0, sizeof(is_streaming));
    memset(is_leader_srrip, 0, sizeof(is_leader_srrip));
    // Assign leader sets for SRRIP and BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_srrip[i] = 1; // first 64: SRRIP
        is_leader_srrip[LLC_SETS - 1 - i] = 2; // last 64: BRRIP
    }
    psel = 512;
    global_access_counter = 0;
}

//--------------------------------------------
// Find victim in the set (RRIP + dead-block)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks predicted dead (dead_ctr==0) and RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (rrpv[set][way] == 3 && dead_ctr[set][way] == 0)
            return way;
    }
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) rrpv[set][way]++;
    }
    return 0;
}

//--------------------------------------------
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
    global_access_counter++;

    // --- Streaming detector ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_delta[set] != 0 && std::abs(delta) == std::abs(last_delta[set]) && (std::abs(delta) < 512*1024)) {
        is_streaming[set] = 1;
    } else {
        is_streaming[set] = 0;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- SHiP-lite signature ---
    uint16_t sig = (PC ^ (PC >> 6)) & ((1 << SIG_BITS) - 1); // 6-bit signature
    uint16_t sig_idx = sig ^ (set & 0xFFF); // index into ship_ctr table

    // --- DRRIP set-dueling ---
    bool use_srrip = false;
    if (is_leader_srrip[set] == 1) use_srrip = true;
    else if (is_leader_srrip[set] == 2) use_srrip = false;
    else use_srrip = (psel >= 512);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // promote
        // Update SHiP outcome counter (increment, max 3)
        if (ship_ctr[sig_idx] < 3) ship_ctr[sig_idx]++;
        // Dead-block predictor: increment reuse counter (max 3)
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
    } else {
        // --- On miss: insertion depth ---
        block_sig[set][way] = sig;
        // Dead-block predictor: reset reuse counter
        dead_ctr[set][way] = 0;

        // Streaming detected: insert at distant RRPV (pollution control)
        if (is_streaming[set]) {
            rrpv[set][way] = 3;
        } else if (ship_ctr[sig_idx] >= 2) {
            rrpv[set][way] = 0; // proven reusable: insert close
        } else {
            // Use DRRIP: SRRIP (insert at 2) or BRRIP (insert at 3 with 1/32 probability)
            if (use_srrip) {
                rrpv[set][way] = 2;
            } else {
                rrpv[set][way] = (rand() % 32 == 0) ? 2 : 3;
            }
        }
    }

    // --- DRRIP set-dueling PSEL update ---
    if (!hit && (is_leader_srrip[set] == 1)) {
        if (hit) { if (psel < 1023) psel++; }
        else { if (psel > 0) psel--; }
    }
    if (!hit && (is_leader_srrip[set] == 2)) {
        if (hit) { if (psel > 0) psel--; }
        else { if (psel < 1023) psel++; }
    }

    // --- On eviction: update SHiP outcome counter ---
    if (!hit && way < LLC_WAYS) {
        uint8_t evicted_sig = block_sig[set][way];
        uint16_t evict_idx = evicted_sig ^ (set & 0xFFF);
        // If block was not reused (rrpv==3), decrement outcome counter
        if (rrpv[set][way] == 3 && ship_ctr[evict_idx] > 0)
            ship_ctr[evict_idx]--;
    }

    // --- Dead-block decay: every DEAD_DECAY_PERIOD accesses, decay all counters ---
    if ((global_access_counter % DEAD_DECAY_PERIOD) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Dead-Block + Streaming Insertion: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (is_streaming[s]) streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "Final PSEL: " << psel << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[Heartbeat] Streaming sets: ";
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (is_streaming[s]) streaming_sets++;
    std::cout << streaming_sets << " | PSEL: " << psel << std::endl;
}