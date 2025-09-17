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

// Per-block: RRPV (2 bits), signature (6 bits)
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t sig;       // 6 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set last address, stride, stream count (3 bits)
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_stride;
    uint8_t stream_cnt; // 3 bits
};
StreamDetect stream_meta[LLC_SETS];

// DRRIP: 64 leader sets for SRRIP, 64 for BRRIP
#define NUM_LEADER_SETS 64
std::vector<uint32_t> leader_srrip;
std::vector<uint32_t> leader_brrip;

// PSEL: 10-bit global selector
uint16_t PSEL = 512;

// Helper: assign leader sets deterministically
void InitLeaderSets() {
    leader_srrip.clear();
    leader_brrip.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_srrip.push_back(i);
        leader_brrip.push_back(i + LLC_SETS/2);
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(ship_table, 0, sizeof(ship_table));
    memset(stream_meta, 0, sizeof(stream_meta));
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

    // --- Streaming detector ---
    StreamDetect &sd = stream_meta[set];
    int64_t stride = paddr - sd.last_addr;
    if (sd.last_stride != 0 && stride == sd.last_stride) {
        if (sd.stream_cnt < 7) sd.stream_cnt++;
    } else {
        sd.stream_cnt = 0;
    }
    sd.last_stride = stride;
    sd.last_addr = paddr;

    // --- On hit: SHiP outcome update, promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        if (ship_table[sig].ctr < 3) ship_table[sig].ctr++;
        // DRRIP PSEL update for leader sets
        bool is_leader_srrip = false, is_leader_brrip = false;
        for (auto s : leader_srrip) if (set == s) is_leader_srrip = true;
        for (auto s : leader_brrip)  if (set == s) is_leader_brrip = true;
        if (is_leader_srrip && PSEL < 1023) PSEL++;
        if (is_leader_brrip && PSEL > 0) PSEL--;
        return;
    }

    // --- On fill: choose insertion depth ---
    bool is_leader_srrip = false, is_leader_brrip = false;
    for (auto s : leader_srrip) if (set == s) is_leader_srrip = true;
    for (auto s : leader_brrip)  if (set == s) is_leader_brrip = true;

    uint8_t ins_rrpv = 3; // default distant

    // Streaming detector: if stream_cnt >= 4, treat as streaming/bypass
    if (sd.stream_cnt >= 4) {
        ins_rrpv = 3; // streaming: insert at distant
    } else {
        // SHiP-lite: if signature counter >=2, insert at 2 (SRRIP); else at 3
        if (ship_table[sig].ctr >= 2)
            ins_rrpv = 2;
        else
            ins_rrpv = 3;
    }

    // Leader sets override insertion
    if (is_leader_srrip)
        ins_rrpv = 2; // SRRIP: always insert at 2
    else if (is_leader_brrip)
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: 1/32 at 2, else 3
    // Normal sets: pick policy based on PSEL
    else if (!is_leader_srrip && !is_leader_brrip) {
        if (PSEL >= 512)
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
    }

    // On fill: set insertion RRPV
    meta[set][way].rrpv = ins_rrpv;
    // Decay SHiP counter for signature on victim (simulate dead-block)
    uint16_t victim_sig = meta[set][way].sig;
    if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t ship_live = 0, ship_dead = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i].ctr >= 2) ship_live++; else ship_dead++;
    std::cout << "SHiP-Lite+Stream: live sigs=" << ship_live << ", dead sigs=" << ship_dead << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed beyond SHiP/streaming
}