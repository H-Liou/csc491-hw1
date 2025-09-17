#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP: 32 leader sets, 10-bit PSEL
#define DIP_LEADER_SETS 32
#define DIP_PSEL_BITS 10
uint16_t dip_psel = (1 << (DIP_PSEL_BITS - 1)); // Start at midpoint
std::vector<uint32_t> dip_leader_sets;

// SHiP-lite: 4-bit signature table, 2-bit outcome counter
#define SHIP_SIG_BITS 4
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
struct ShipEntry {
    uint8_t ctr; // 2 bits
};
ShipEntry ship_table[SHIP_SIG_ENTRIES];

// Per-block: RRPV (2 bits), signature (4 bits), streaming flag (1 bit)
struct BlockMeta {
    uint8_t rrpv;    // 2 bits
    uint8_t sig;     // 4 bits
    uint8_t stream;  // 1 bit
    uint64_t last_addr; // For stride detection
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Helper: assign leader sets for DIP
void InitLeaderSets() {
    dip_leader_sets.clear();
    for (uint32_t i = 0; i < DIP_LEADER_SETS; ++i)
        dip_leader_sets.push_back(i);
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(ship_table, 0, sizeof(ship_table));
    dip_psel = (1 << (DIP_PSEL_BITS - 1));
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
    // 1. Prefer invalid
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // 2. Prefer RRPV==3
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
    uint8_t sig = (PC ^ (PC >> 4) ^ (PC >> 8)) & ((1 << SHIP_SIG_BITS) - 1);

    // --- Streaming detection: mark block as streaming if stride matches last_addr ---
    uint8_t is_streaming = 0;
    int64_t stride = 0;
    if (meta[set][way].last_addr != 0)
        stride = paddr - meta[set][way].last_addr;
    if (stride != 0 && stride == (meta[set][way].last_addr - victim_addr))
        is_streaming = 1;
    meta[set][way].last_addr = paddr;

    // --- DIP: determine if set is leader ---
    uint8_t is_lip_leader = 0, is_bip_leader = 0;
    for (int i = 0; i < DIP_LEADER_SETS; ++i) {
        if (set == dip_leader_sets[i]) {
            if (i < DIP_LEADER_SETS / 2) is_lip_leader = 1;
            else is_bip_leader = 1;
            break;
        }
    }
    // DIP: choose policy
    bool use_lip = false;
    if (is_lip_leader) use_lip = true;
    else if (is_bip_leader) use_lip = false;
    else use_lip = (dip_psel >= (1 << (DIP_PSEL_BITS - 1)));

    // --- On hit: update SHiP and promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        meta[set][way].sig = sig;
        meta[set][way].stream = 0;
        if (ship_table[sig].ctr < 3) ship_table[sig].ctr++;
        // DIP: update PSEL for leader sets
        if (is_lip_leader && dip_psel < ((1 << DIP_PSEL_BITS) - 1)) dip_psel++;
        if (is_bip_leader && dip_psel > 0) dip_psel--;
        return;
    }

    // --- On fill: streaming bypass ---
    if (is_streaming) {
        meta[set][way].rrpv = 3; // insert at distant RRPV
        meta[set][way].sig = sig;
        meta[set][way].stream = 1;
        // Decay SHiP counter for victim
        uint8_t victim_sig = meta[set][way].sig;
        if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;
        return;
    }

    // --- DIP insertion depth ---
    uint8_t ins_rrpv = 3; // default distant
    if (use_lip) {
        ins_rrpv = 3; // LIP: always insert at LRU
    } else {
        // BIP: insert at MRU (RRPV=0) with probability 1/32, else at LRU (RRPV=3)
        static uint32_t bip_ctr = 0;
        if ((bip_ctr++ & 0x1F) == 0)
            ins_rrpv = 0;
        else
            ins_rrpv = 3;
    }
    // --- SHiP-lite bias ---
    uint8_t ship_conf = ship_table[sig].ctr;
    if (ship_conf >= 2)
        ins_rrpv = 1; // likely reused

    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].sig = sig;
    meta[set][way].stream = 0;

    // --- Decay SHiP counter for victim ---
    uint8_t victim_sig = meta[set][way].sig;
    if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t ship_live = 0, ship_dead = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i].ctr >= 2) ship_live++; else ship_dead++;
    uint32_t streaming_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].stream) streaming_blocks++;
    std::cout << "DSS: live sigs=" << ship_live
              << ", dead sigs=" << ship_dead
              << ", streaming blocks=" << streaming_blocks
              << ", DIP_PSEL=" << dip_psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Could periodically decay SHiP counters or streaming flags if desired
}