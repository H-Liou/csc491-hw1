#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 4-bit signature per block, 2-bit outcome counter per signature (256 entries)
uint8_t sig[LLC_SETS][LLC_WAYS];        // 4-bit signature per block
uint8_t ship_ctr[256];                  // 2-bit reuse counter per signature (indexed by PC low 8 bits)

// Streaming detector: per-set, last addr/delta, 1-bit flag, 3-bit confidence
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_flag[LLC_SETS]; // 1 bit/set
uint8_t stream_conf[LLC_SETS];    // 3 bits/set

// DRRIP set-dueling: 32 leader sets, 10-bit PSEL
const uint32_t NUM_LEADER_SETS = 32;
bool is_leader_set_srrip[LLC_SETS];
bool is_leader_set_brrip[LLC_SETS];
uint16_t PSEL = 512; // 10 bits, mid-value

// Helper: assign leader sets for SRRIP/BRRIP
void AssignLeaderSets() {
    memset(is_leader_set_srrip, 0, sizeof(is_leader_set_srrip));
    memset(is_leader_set_brrip, 0, sizeof(is_leader_set_brrip));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set_srrip[(i * LLC_SETS) / NUM_LEADER_SETS] = true;
        is_leader_set_brrip[(i * LLC_SETS) / NUM_LEADER_SETS + 1] = true;
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU on reset
    memset(sig, 0, sizeof(sig));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // optimistic
    PSEL = 512; // midpoint
    AssignLeaderSets();
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(stream_conf, 0, sizeof(stream_conf));
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming: prefer bypass (insert at LRU)
    if (streaming_flag[set]) {
        // Find invalid block first
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        // Otherwise, pick block with RRPV==3
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment RRPV until found
        while (true) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] == 3)
                    return way;
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] < 3)
                    rrpv[set][way]++;
        }
    }

    // RRIP fallback: pick block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
    // Increment RRPV until found
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
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
    // --- Streaming detector update ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_conf[set] < 7) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    last_addr[set] = paddr;
    last_delta[set] = delta;
    streaming_flag[set] = (stream_conf[set] >= 5) ? 1 : 0;

    // --- DRRIP set-dueling: choose insertion policy ---
    bool use_srrip = false, use_brrip = false;
    if (is_leader_set_srrip[set]) use_srrip = true;
    else if (is_leader_set_brrip[set]) use_brrip = true;
    else use_brrip = (PSEL >= 512);

    // --- Get PC signature (4 bits from PC, e.g. bits 6–9) ---
    uint8_t pc_sig = (PC >> 6) & 0xF; // 4-bit signature
    uint8_t sig_idx = PC & 0xFF;      // 8 bits for global table

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // SHiP: outcome counter update
        if (ship_ctr[sig_idx] < 3) ship_ctr[sig_idx]++;
        return;
    }

    // --- On cache miss or fill ---
    uint8_t ins_rrpv = 3; // default LRU

    // Streaming: bypass insertion (insert at LRU)
    if (streaming_flag[set]) {
        ins_rrpv = 3;
    }
    // SHiP insertion logic: use outcome counter to bias RRPV
    else if (ship_ctr[sig_idx] >= 2) {
        ins_rrpv = 0; // High reuse: insert at MRU
    }
    else if (ship_ctr[sig_idx] == 1) {
        ins_rrpv = 2; // Moderate reuse: insert at mid-RRPV
    }
    else { // ship_ctr[sig_idx] == 0
        // Use set-dueling for ambiguous/poor reuse signatures
        if (use_brrip) {
            static uint32_t brrip_ctr = 0;
            if ((brrip_ctr++ % 32) == 0)
                ins_rrpv = 2; // BRRIP: insert at RRPV=2 rarely
            else
                ins_rrpv = 3;
        } else if (use_srrip) {
            ins_rrpv = 2; // SRRIP: insert at RRPV=2
        }
    }

    rrpv[set][way] = ins_rrpv;
    sig[set][way] = pc_sig;

    // On eviction (if not reused), penalize outcome counter for previous signature
    uint8_t victim_sig_idx = (victim_addr != 0) ? (victim_addr & 0xFF) : sig_idx;
    if (!hit && rrpv[set][way] == 3 && ship_ctr[victim_sig_idx] > 0)
        ship_ctr[victim_sig_idx]--;

    // PSEL: hits/misses in leader sets
    if (is_leader_set_srrip[set] && !hit && PSEL > 0) PSEL--;
    if (is_leader_set_brrip[set] && !hit && PSEL < 1023) PSEL++;
    if (is_leader_set_srrip[set] && hit && PSEL < 1023) PSEL++;
    if (is_leader_set_brrip[set] && hit && PSEL > 0) PSEL--;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s])
            streaming_sets++;
    std::cout << "SHiP-DRRIP-SB: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // SHiP outcome counter histogram
    uint64_t ctr_hist[4] = {0};
    for (int i = 0; i < 256; ++i)
        ctr_hist[ship_ctr[i]]++;
    std::cout << "SHiP-DRRIP-SB: SHiP outcome counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << ctr_hist[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "SHiP-DRRIP-SB: SRRIP/BRRIP PSEL = " << (int)PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: every heartbeat, decay all SHiP outcome counters by 1 if >0
    for (int i = 0; i < 256; ++i)
        if (ship_ctr[i] > 0)
            ship_ctr[i]--;
}