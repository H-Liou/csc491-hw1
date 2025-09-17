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

// SHiP-lite: 6-bit PC signature per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS];      // 6 bits/block

// SHiP-lite: 64-entry outcome table (indexed by signature), 2 bits/entry
uint8_t ship_table[64]; // 2 bits per entry

// DIP: 8-bit PSEL
uint8_t PSEL = 128; // 8 bits, mid-value

// DIP: 32 leader sets (16 LIP, 16 BIP)
const uint32_t NUM_LEADER_SETS = 32;
const uint32_t LEADER_SETS_LIP = 16;
const uint32_t LEADER_SETS_BIP = 16;
bool is_leader_set_lip[LLC_SETS];
bool is_leader_set_bip[LLC_SETS];

// Streaming detector: per-set, tracks last address and delta, 1-bit streaming flag
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_flag[LLC_SETS]; // 1 bit/set

// Streaming detector: per-set, 3-bit confidence counter
uint8_t stream_conf[LLC_SETS]; // 3 bits/set

// Helper: hash PC to 6 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Assign leader sets for DIP
void AssignLeaderSets() {
    memset(is_leader_set_lip, 0, sizeof(is_leader_set_lip));
    memset(is_leader_set_bip, 0, sizeof(is_leader_set_bip));
    for (uint32_t i = 0; i < LEADER_SETS_LIP; ++i)
        is_leader_set_lip[(i * LLC_SETS) / NUM_LEADER_SETS] = true;
    for (uint32_t i = 0; i < LEADER_SETS_BIP; ++i)
        is_leader_set_bip[(i * LLC_SETS) / NUM_LEADER_SETS + 1] = true;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    PSEL = 128; // midpoint
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
    // Streaming: if streaming_flag is set, prefer block with RRPV==3
    if (streaming_flag[set]) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // If none, increment RRPV and retry
        while (true) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] == 3)
                    return way;
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] < 3)
                    rrpv[set][way]++;
        }
    }

    // Non-streaming: normal RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
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

    // --- SHiP-lite signature ---
    uint8_t sig = pc_hash(PC);

    // --- DIP insertion policy selection ---
    bool use_lip = false, use_bip = false;
    if (is_leader_set_lip[set]) use_lip = true;
    else if (is_leader_set_bip[set]) use_bip = true;
    else use_lip = (PSEL >= 128);

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Update SHiP outcome
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
        // DIP: On hit in leader sets, increment PSEL for LIP, decrement for BIP
        if (is_leader_set_lip[set] && PSEL < 255) PSEL++;
        if (is_leader_set_bip[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- On cache miss or fill ---
    uint8_t ins_rrpv;
    if (streaming_flag[set]) {
        // Streaming: bypass (do not insert) if possible, else insert at distant RRPV
        ins_rrpv = 3; // Insert at LRU
    } else if (use_lip) {
        ins_rrpv = 3; // LRU
    } else if (use_bip) {
        // BIP: insert at LRU only every 1/32, else at MRU+1
        static uint32_t bip_counter = 0;
        if ((bip_counter++ % 32) == 0)
            ins_rrpv = 3;
        else
            ins_rrpv = 1;
    } else {
        // Dynamic: use PSEL winner
        ins_rrpv = (PSEL >= 128) ? 3 : 1;
    }

    // SHiP bias: if PC signature is frequently reused, insert at MRU
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;

    // Update block metadata
    pc_sig[set][way] = sig;
    rrpv[set][way] = ins_rrpv;
    // SHiP outcome: weak initial prediction
    if (ship_table[sig] > 0) ship_table[sig]--;
    // DIP: On miss in leader sets, decrement PSEL for LIP, increment for BIP
    if (is_leader_set_lip[set] && PSEL > 0) PSEL--;
    if (is_leader_set_bip[set] && PSEL < 255) PSEL++;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s])
            streaming_sets++;
    std::cout << "SLSBAI: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // SHiP table summary
    std::cout << "SLSBAI: SHiP table (reuse counters): ";
    for (int i = 0; i < 64; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "SLSBAI: DIP PSEL = " << (int)PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set ratio or PSEL
}