#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block, 10-bit PSEL, set-dueling (SRRIP vs BRRIP)
#define PSEL_BITS 10
uint16_t PSEL = 1 << (PSEL_BITS - 1); // 512

// SHiP-lite: 6-bit PC signature, 2-bit outcome counter
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

// DRRIP set-dueling: first 32 sets are SRRIP leaders, next 32 are BRRIP leaders
std::vector<uint32_t> sr_leader_sets, br_leader_sets;
void InitLeaderSets() {
    sr_leader_sets.clear();
    br_leader_sets.clear();
    for (uint32_t i = 0; i < 32; ++i)
        sr_leader_sets.push_back(i);
    for (uint32_t i = 32; i < 64; ++i)
        br_leader_sets.push_back(i);
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(ship_table, 0, sizeof(ship_table));
    PSEL = 1 << (PSEL_BITS - 1);
    InitLeaderSets();
}

// Find victim in the set (prefer invalid, else RRPV==3, else increment RRPV)
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
    return 0;
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

    // --- On hit: ---
    if (hit) {
        meta[set][way].rrpv = 0; // MRU
        meta[set][way].dead_ctr = 0; // block reused
        if (ship_table[sig].ctr < 3) ship_table[sig].ctr++;
        return;
    }

    // --- On eviction: update dead-block counter ---
    uint8_t victim_dead = meta[set][way].dead_ctr;
    if (victim_dead < 3) meta[set][way].dead_ctr++;
    // Decay SHiP counter for victim signature
    uint16_t victim_sig = meta[set][way].sig;
    if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;

    // --- On fill: ---
    meta[set][way].sig = sig;
    uint8_t ship_conf = ship_table[sig].ctr;
    uint8_t dead_conf = meta[set][way].dead_ctr;

    // DRRIP set-dueling: pick insertion depth
    bool is_sr_leader = std::find(sr_leader_sets.begin(), sr_leader_sets.end(), set) != sr_leader_sets.end();
    bool is_br_leader = std::find(br_leader_sets.begin(), br_leader_sets.end(), set) != br_leader_sets.end();
    uint8_t ins_rrpv = 3; // default distant

    if (dead_conf >= 2) {
        ins_rrpv = 3; // dead on arrival
    } else if (ship_conf >= 2) {
        // likely to be reused
        if (is_sr_leader) {
            ins_rrpv = 2; // SRRIP
        } else if (is_br_leader) {
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at distant with high probability
        } else {
            // follower: use PSEL
            if (PSEL >= (1 << (PSEL_BITS - 1)))
                ins_rrpv = 2;
            else
                ins_rrpv = (rand() % 32 == 0) ? 2 : 3;
        }
    } else {
        // unknown signature: conservative
        ins_rrpv = 3;
    }
    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].dead_ctr = 0;

    // Update PSEL for leader sets
    if (is_sr_leader && !hit) {
        if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    } else if (is_br_leader && !hit) {
        if (PSEL > 0) PSEL--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t ship_live = 0, ship_dead = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i].ctr >= 2) ship_live++; else ship_dead++;
    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].dead_ctr >= 2) dead_blocks++;
    std::cout << "DRRIP+SHIP+Dead: live sigs=" << ship_live
              << ", dead sigs=" << ship_dead
              << ", dead blocks=" << dead_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    static uint64_t heartbeat = 0;
    heartbeat++;
    // Periodic decay of dead-block counters (every 100K accesses)
    if (heartbeat % 100000 == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (meta[s][w].dead_ctr > 0)
                    meta[s][w].dead_ctr--;
    }
}