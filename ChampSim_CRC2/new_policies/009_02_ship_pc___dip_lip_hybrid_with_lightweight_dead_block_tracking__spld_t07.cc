#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 6-bit PC signature/block
uint8_t pc_sig[LLC_SETS][LLC_WAYS];

// SHiP table: 64-entry, 2 bits/entry
uint8_t ship_table[64];

// DIP: 10-bit PSEL, 64 leader sets (32 LIP, 32 BIP)
uint16_t PSEL = 512;
bool is_leader_set_lip[LLC_SETS];
bool is_leader_set_bip[LLC_SETS];

// Dead-block: 2 bits/block (max 3, decayed periodically)
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// DIP config
const uint32_t NUM_LEADER_SETS = 64;
const uint32_t LEADER_SETS_LIP = 32;
const uint32_t LEADER_SETS_BIP = 32;

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// BIP: insert at MRU only every 1/32
const uint32_t BIP_INTERVAL = 32;
uint32_t bip_insertion_counter = 0;

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
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weak initial reuse
    memset(dead_ctr, 0, sizeof(dead_ctr));
    PSEL = 512;
    AssignLeaderSets();
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
    // Dead-block RRIP: prefer blocks with RRPV==RRIP_MAX
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    // If none, increment RRPV and retry
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < RRIP_MAX)
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
    // --- SHiP signature ---
    uint8_t sig = pc_hash(PC);

    // --- DIP insertion policy selection ---
    bool use_lip = false, use_bip = false;
    if (is_leader_set_lip[set]) use_lip = true;
    else if (is_leader_set_bip[set]) use_bip = true;
    else use_lip = (PSEL >= 512);

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = RRIP_MRU;
        // Update SHiP outcome
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
        // Dead-block: increment reuse counter (max 3)
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        // DIP: On hit in leader sets, increment PSEL for LIP, decrement for BIP
        if (is_leader_set_lip[set] && PSEL < 1023) PSEL++;
        if (is_leader_set_bip[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- On fill/miss ---
    uint8_t ins_rrpv;
    if (use_lip) {
        ins_rrpv = RRIP_MAX; // LIP: always insert at LRU
    } else if (use_bip) {
        // BIP: insert at MRU only every 1/32, else LRU
        if ((bip_insertion_counter++ % BIP_INTERVAL) == 0)
            ins_rrpv = RRIP_MRU;
        else
            ins_rrpv = RRIP_MAX;
    } else {
        // Dynamic: use PSEL winner
        ins_rrpv = (PSEL >= 512) ? RRIP_MAX : RRIP_MRU;
    }

    // SHiP bias: if PC signature is frequently reused, insert at MRU
    if (ship_table[sig] >= 2)
        ins_rrpv = RRIP_MRU;

    // Dead-block bias: if line has recent reuse, insert at MRU
    if (dead_ctr[set][way] >= 2)
        ins_rrpv = RRIP_MRU;

    // Update block metadata
    pc_sig[set][way] = sig;
    rrpv[set][way] = ins_rrpv;
    dead_ctr[set][way] = 0; // Reset dead-block counter on fill
    if (ship_table[sig] > 0) ship_table[sig]--; // SHiP outcome: weak initial
    // DIP: On miss in leader sets, decrement PSEL for LIP, increment for BIP
    if (is_leader_set_lip[set] && PSEL > 0) PSEL--;
    if (is_leader_set_bip[set] && PSEL < 1023) PSEL++;
}

// Decay dead-block counters periodically (call every N million accesses)
void DecayDeadBlockCounters() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] > 0)
                dead_ctr[set][way]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint64_t reused_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] >= 2)
                reused_lines++;
    std::cout << "SPLD: Lines with recent reuse: " << reused_lines << std::endl;

    // SHiP table summary
    std::cout << "SPLD: SHiP table (reuse counters): ";
    for (int i = 0; i < 64; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "SPLD: DIP PSEL = " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print dead-block counter distribution or PSEL
}