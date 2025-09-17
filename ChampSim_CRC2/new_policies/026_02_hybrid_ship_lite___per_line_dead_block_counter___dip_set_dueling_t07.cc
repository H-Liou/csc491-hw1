#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit PC signature table, 2-bit outcome counter
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024
struct ShipEntry {
    uint8_t ctr; // 2 bits
};
ShipEntry ship_table[SHIP_SIG_ENTRIES];

// Per-block: RRPV (2 bits), signature (6 bits), dead-block counter (2 bits)
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t sig;       // 6 bits
    uint8_t dead_ctr;  // 2 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// DIP-style: 64 leader sets for LIP, 64 for BIP, 10-bit PSEL
#define NUM_LEADER_SETS 64
std::vector<uint32_t> leader_lip;
std::vector<uint32_t> leader_bip;
uint16_t PSEL = 512;

// Helper: assign leader sets deterministically
void InitLeaderSets() {
    leader_lip.clear();
    leader_bip.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_lip.push_back(i);
        leader_bip.push_back(i + LLC_SETS/2);
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(ship_table, 0, sizeof(ship_table));
    InitLeaderSets();
    PSEL = 512;
}

// Find victim in the set (prefer invalid, else RRPV==3)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
                meta[set][way].rrpv++;
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
    // --- SHiP-lite signature ---
    uint16_t sig = (PC ^ (PC >> 6) ^ (PC >> 12)) & ((1 << SHIP_SIG_BITS) - 1);
    meta[set][way].sig = sig;

    // --- On hit: update SHiP and dead-block counter, promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        if (ship_table[sig].ctr < 3)
            ship_table[sig].ctr++;
        if (meta[set][way].dead_ctr < 3)
            meta[set][way].dead_ctr++; // mark as reused
        // DIP PSEL update for leader sets
        bool is_leader_lip = false, is_leader_bip = false;
        for (auto s : leader_lip) if (set == s) is_leader_lip = true;
        for (auto s : leader_bip) if (set == s) is_leader_bip = true;
        if (is_leader_lip && PSEL > 0) PSEL--;
        if (is_leader_bip && PSEL < 1023) PSEL++;
        return;
    }

    // --- On fill: choose insertion depth ---
    bool is_leader_lip = false, is_leader_bip = false;
    for (auto s : leader_lip) if (set == s) is_leader_lip = true;
    for (auto s : leader_bip) if (set == s) is_leader_bip = true;

    // Use dead-block counter if available
    uint8_t ins_rrpv = 3; // default distant
    if (meta[set][way].dead_ctr >= 2) {
        ins_rrpv = 2; // recently reused block: retain longer
    } else {
        ins_rrpv = 3;
    }
    // SHiP-lite: if signature counter >=2, also promote
    if (ship_table[sig].ctr >= 2)
        ins_rrpv = 2;

    // DIP set-dueling overrides
    if (is_leader_lip)
        ins_rrpv = 3; // LIP: always insert at LRU
    else if (is_leader_bip)
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BIP: mostly LRU, rare MRU
    else {
        if (PSEL >= 512)
            ins_rrpv = 3; // LIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BIP
    }

    // On fill: set insertion RRPV, reset dead-block counter
    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].dead_ctr = 0;

    // Decay SHiP counter for signature on victim (simulate dead-block)
    uint16_t victim_sig = meta[set][way].sig;
    if (ship_table[victim_sig].ctr > 0)
        ship_table[victim_sig].ctr--;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t ship_live = 0, ship_dead = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i].ctr >= 2) ship_live++; else ship_dead++;
    std::cout << "Hybrid SHiP+Dead+DIP: live sigs=" << ship_live
              << ", dead sigs=" << ship_dead
              << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodically decay dead-block counters (every N calls)
    static uint32_t heartbeat_cnt = 0;
    heartbeat_cnt++;
    if (heartbeat_cnt % 500000 == 0) {
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (meta[set][way].dead_ctr > 0)
                    meta[set][way].dead_ctr--;
    }
}