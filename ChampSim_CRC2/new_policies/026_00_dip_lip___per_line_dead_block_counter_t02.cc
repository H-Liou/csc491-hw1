#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP: 64 leader sets for LIP, 64 for BIP
#define NUM_LEADER_SETS 64
std::vector<uint32_t> leader_lip;
std::vector<uint32_t> leader_bip;

// PSEL: 10-bit global selector
uint16_t PSEL = 512;

// Per-block: RRPV (2 bits), dead-block counter (2 bits)
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t dead_ctr;  // 2 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

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
    // --- DIP leader set detection ---
    bool is_leader_lip = false, is_leader_bip = false;
    for (auto s : leader_lip) if (set == s) is_leader_lip = true;
    for (auto s : leader_bip) if (set == s) is_leader_bip = true;

    // --- On hit: promote to MRU, reset dead-block counter ---
    if (hit) {
        meta[set][way].rrpv = 0;
        meta[set][way].dead_ctr = 0;
        // DIP PSEL update for leader sets
        if (is_leader_lip && PSEL < 1023) PSEL++;
        if (is_leader_bip && PSEL > 0) PSEL--;
        return;
    }

    // --- On fill: choose insertion depth ---
    uint8_t ins_rrpv = 3; // default distant

    // Dead-block counter: if victim's dead_ctr >=2, insert at distant
    if (meta[set][way].dead_ctr >= 2) {
        ins_rrpv = 3;
    } else {
        // DIP: leader sets override insertion
        if (is_leader_lip)
            ins_rrpv = 3; // LIP: always insert at distant
        else if (is_leader_bip)
            ins_rrpv = (rand() % 32 == 0) ? 0 : 3; // BIP: 1/32 at MRU, else distant
        // Normal sets: pick policy based on PSEL
        else {
            if (PSEL >= 512)
                ins_rrpv = 3; // LIP
            else
                ins_rrpv = (rand() % 32 == 0) ? 0 : 3; // BIP
        }
    }

    // On fill: set insertion RRPV
    meta[set][way].rrpv = ins_rrpv;
    // On eviction: increment dead-block counter (max 3)
    if (meta[set][way].dead_ctr < 3) meta[set][way].dead_ctr++;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t dead0 = 0, dead1 = 0, dead2 = 0, dead3 = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            switch (meta[set][way].dead_ctr) {
                case 0: dead0++; break;
                case 1: dead1++; break;
                case 2: dead2++; break;
                case 3: dead3++; break;
            }
        }
    std::cout << "DIP-LIP+DeadBlock: dead_ctr[0]=" << dead0
              << " dead_ctr[1]=" << dead1
              << " dead_ctr[2]=" << dead2
              << " dead_ctr[3]=" << dead3
              << " PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed for dead-block counters
}