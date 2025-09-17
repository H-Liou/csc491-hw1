#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_counter[SHIP_SIG_ENTRIES]; // 2 bits per signature
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block

// Streaming detector: per-set, last addr/delta, 1-bit flag, 3-bit confidence
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_flag[LLC_SETS]; // 1 bit/set
uint8_t stream_conf[LLC_SETS];    // 3 bits/set

// DIP set-dueling: 32 leader sets, 10-bit PSEL
const uint32_t NUM_LEADER_SETS = 32;
bool is_leader_set_lip[LLC_SETS];
bool is_leader_set_bip[LLC_SETS];
uint16_t PSEL = 512; // 10 bits, mid-value

// RRIP metadata: 2 bits/block (for victim selection)
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Helper: assign leader sets for LIP/BIP
void AssignLeaderSets() {
    memset(is_leader_set_lip, 0, sizeof(is_leader_set_lip));
    memset(is_leader_set_bip, 0, sizeof(is_leader_set_bip));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set_lip[(i * LLC_SETS) / NUM_LEADER_SETS] = true;
        is_leader_set_bip[(i * LLC_SETS) / NUM_LEADER_SETS + 1] = true;
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(ship_counter, 1, sizeof(ship_counter)); // neutral start
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(rrpv, 3, sizeof(rrpv)); // LRU on reset
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

    // --- SHiP signature extraction ---
    uint8_t sig = (PC ^ (PC >> 6) ^ (PC >> 12)) & (SHIP_SIG_ENTRIES - 1);

    // --- DIP set-dueling: choose insertion policy ---
    bool use_lip = false, use_bip = false;
    if (is_leader_set_lip[set]) use_lip = true;
    else if (is_leader_set_bip[set]) use_bip = true;
    else use_bip = (PSEL >= 512);

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // SHiP: increment outcome counter for signature (max 3)
        if (ship_counter[ship_signature[set][way]] < 3)
            ship_counter[ship_signature[set][way]]++;
        return;
    }

    // --- On cache miss or fill ---
    uint8_t ins_rrpv = 3; // default LRU

    // Streaming: bypass insertion (do not update block metadata)
    if (streaming_flag[set]) {
        // Champsim always inserts, so insert at LRU
        ins_rrpv = 3;
    }
    // SHiP: use signature counter to bias insertion
    else if (ship_counter[sig] >= 2) {
        ins_rrpv = 0; // high reuse: insert at MRU
    }
    else if (ship_counter[sig] == 0) {
        ins_rrpv = 3; // dead-block: insert at LRU
    }
    // DIP set-dueling for ambiguous signatures
    else if (use_bip) {
        static uint32_t bip_ctr = 0;
        if ((bip_ctr++ % 32) == 0)
            ins_rrpv = 0; // BIP: insert at MRU rarely
        else
            ins_rrpv = 3;
    }
    else if (use_lip) {
        ins_rrpv = 3; // LIP: always insert at LRU
    }

    // Update block metadata
    rrpv[set][way] = ins_rrpv;
    ship_signature[set][way] = sig;

    // On eviction without reuse, decrement SHiP counter for evicted signature
    if (!hit && rrpv[set][way] == 3) {
        uint8_t evict_sig = ship_signature[set][way];
        if (ship_counter[evict_sig] > 0)
            ship_counter[evict_sig]--;
    }

    // PSEL: update on leader set misses/hits
    if (is_leader_set_lip[set] && !hit && PSEL > 0) PSEL--;
    if (is_leader_set_bip[set] && !hit && PSEL < 1023) PSEL++;
    if (is_leader_set_lip[set] && hit && PSEL < 1023) PSEL++;
    if (is_leader_set_bip[set] && hit && PSEL > 0) PSEL--;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s])
            streaming_sets++;
    std::cout << "SHiP-SB-DIP: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // SHiP counter histogram
    uint64_t ship_hist[4] = {0};
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        ship_hist[ship_counter[i]]++;
    std::cout << "SHiP-SB-DIP: SHiP counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << ship_hist[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "SHiP-SB-DIP: DIP PSEL = " << (int)PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed for SHiP counters (they self-adapt)
}