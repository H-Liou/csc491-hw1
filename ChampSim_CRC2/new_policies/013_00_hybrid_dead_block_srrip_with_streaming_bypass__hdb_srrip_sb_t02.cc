#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Per-line Dead Block Counter: 2 bits/block
uint8_t dbc[LLC_SETS][LLC_WAYS]; // 2 bits/block

// SRRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set, last addr/delta, 1-bit flag, 3-bit confidence
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_flag[LLC_SETS]; // 1 bit/set
uint8_t stream_conf[LLC_SETS];    // 3 bits/set

// SRRIP/BRRIP set-dueling: 32 leader sets, 10-bit PSEL
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
    memset(dbc, 0, sizeof(dbc));
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
    // Streaming: prefer bypass (do not insert, victim is invalid)
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

    // --- SRRIP/BRRIP set-dueling: choose insertion policy ---
    bool use_srrip = false, use_brrip = false;
    if (is_leader_set_srrip[set]) use_srrip = true;
    else if (is_leader_set_brrip[set]) use_brrip = true;
    else use_brrip = (PSEL >= 512);

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        dbc[set][way] = 0;  // Reset DBC on reuse
        // PSEL: hits in leader sets
        if (is_leader_set_srrip[set] && PSEL < 1023) PSEL++;
        if (is_leader_set_brrip[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- On cache miss or fill ---
    uint8_t ins_rrpv = 3; // default LRU

    // Streaming: bypass insertion (do not update block metadata)
    if (streaming_flag[set]) {
        // Champsim always inserts, so insert at LRU
        ins_rrpv = 3;
    }
    // Dead-block: if DBC is high, insert at distant RRPV (evict quickly)
    else if (dbc[set][way] >= 2) {
        ins_rrpv = 3;
    }
    // Dead-block: if DBC is low, insert at MRU
    else if (dbc[set][way] == 0) {
        ins_rrpv = 0;
    }
    // SRRIP/BRRIP: set-dueling for ambiguous DBC
    else if (use_brrip) {
        static uint32_t brrip_ctr = 0;
        if ((brrip_ctr++ % 32) == 0)
            ins_rrpv = 2; // BRRIP: insert at RRPV=2 rarely
        else
            ins_rrpv = 3;
    }
    else if (use_srrip) {
        ins_rrpv = 2; // SRRIP: insert at RRPV=2
    }

    // Update block metadata
    rrpv[set][way] = ins_rrpv;
    // On fill, decay DBC (approximate periodic decay)
    if (dbc[set][way] > 0) dbc[set][way]--;

    // On eviction without reuse, increment DBC (dead block)
    if (!hit && rrpv[set][way] == 3 && dbc[set][way] < 3)
        dbc[set][way]++;

    // PSEL: misses in leader sets
    if (is_leader_set_srrip[set] && PSEL > 0) PSEL--;
    if (is_leader_set_brrip[set] && PSEL < 1023) PSEL++;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s])
            streaming_sets++;
    std::cout << "HDB-SRRIP-SB: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // DBC histogram
    uint64_t dbc_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            dbc_hist[dbc[s][w]]++;
    std::cout << "HDB-SRRIP-SB: Dead-block counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << dbc_hist[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "HDB-SRRIP-SB: SRRIP/BRRIP PSEL = " << (int)PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic DBC decay: every heartbeat, decay all DBC by 1 if >0
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dbc[s][w] > 0)
                dbc[s][w]--;
}