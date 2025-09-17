#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block, 10-bit PSEL
uint16_t PSEL = 512; // 10 bits, 0..1023

// SHiP-lite: 6-bit signature table, 2-bit outcome counter
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024
struct ShipEntry {
    uint8_t ctr; // 2 bits
};
ShipEntry ship_table[SHIP_SIG_ENTRIES];

// Per-block: RRPV (2 bits), signature (6 bits)
struct BlockMeta {
    uint8_t rrpv; // 2 bits
    uint8_t sig;  // 6 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Streaming detector: per-leader-set last_addr, last_stride, stream_cnt (3 bits)
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_stride;
    uint8_t stream_cnt; // 3 bits
};
StreamDetect stream_meta[32]; // Only for 32 streaming leader sets

// Leader sets for streaming detection (sets 0..31)
std::vector<uint32_t> stream_leader_sets;

// DRRIP set-dueling: sets 0..15 for SRRIP, 16..31 for BRRIP
std::vector<uint32_t> SRRIP_leader_sets;
std::vector<uint32_t> BRRIP_leader_sets;

// Helper: assign leader sets for streaming and DRRIP
void InitLeaderSets() {
    stream_leader_sets.clear();
    SRRIP_leader_sets.clear();
    BRRIP_leader_sets.clear();
    for (uint32_t i = 0; i < 32; ++i) {
        stream_leader_sets.push_back(i);
        if (i < 16) SRRIP_leader_sets.push_back(i);
        else BRRIP_leader_sets.push_back(i);
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
    uint16_t sig = (PC ^ (PC >> 6) ^ (PC >> 12)) & ((1 << SHIP_SIG_BITS) - 1);

    // --- Streaming detection (only in leader sets) ---
    uint8_t is_stream_leader = 0;
    int stream_idx = -1;
    for (int i = 0; i < 32; ++i) {
        if (set == stream_leader_sets[i]) {
            is_stream_leader = 1;
            stream_idx = i;
            break;
        }
    }
    bool streaming_bypass = false;
    if (is_stream_leader && stream_idx >= 0) {
        StreamDetect &sd = stream_meta[stream_idx];
        int64_t stride = paddr - sd.last_addr;
        if (sd.last_stride != 0 && stride == sd.last_stride) {
            if (sd.stream_cnt < 7) sd.stream_cnt++;
        } else {
            sd.stream_cnt = 0;
        }
        sd.last_stride = stride;
        sd.last_addr = paddr;
        // If streaming detected, enable bypass
        if (sd.stream_cnt >= 4)
            streaming_bypass = true;
    }

    // --- On hit: update SHiP and promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        meta[set][way].sig = sig;
        if (ship_table[sig].ctr < 3) ship_table[sig].ctr++;
        return;
    }

    // --- On fill: streaming bypass in leader sets ---
    if (streaming_bypass) {
        // Streaming detected: bypass fill (simulate by marking block as distant RRPV)
        meta[set][way].rrpv = 3;
        meta[set][way].sig = sig;
        // Decay SHiP counter for victim
        uint16_t victim_sig = meta[set][way].sig;
        if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;
        return;
    }

    // --- DRRIP set-dueling: determine insertion depth ---
    bool is_srrip_leader = false, is_brrip_leader = false;
    for (int i = 0; i < 16; ++i)
        if (set == SRRIP_leader_sets[i]) is_srrip_leader = true;
    for (int i = 0; i < 16; ++i)
        if (set == BRRIP_leader_sets[i]) is_brrip_leader = true;

    uint8_t ins_rrpv = 2; // SRRIP default: RRPV=2
    if (is_srrip_leader)
        ins_rrpv = 2; // SRRIP: insert at RRPV=2
    else if (is_brrip_leader)
        ins_rrpv = 3; // BRRIP: insert at RRPV=3
    else
        ins_rrpv = (PSEL >= 512) ? 2 : 3; // PSEL majority: SRRIP or BRRIP

    // --- SHiP-lite: bias insertion depth for strong signatures ---
    uint8_t ship_conf = ship_table[sig].ctr;
    if (ship_conf >= 2)
        ins_rrpv = 0; // very likely reused, insert at MRU

    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].sig = sig;

    // --- Decay SHiP counter for victim ---
    uint16_t victim_sig = meta[set][way].sig;
    if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;

    // --- DRRIP set-dueling: update PSEL ---
    if (is_srrip_leader && !hit) {
        if (PSEL < 1023) PSEL++;
    }
    if (is_brrip_leader && !hit) {
        if (PSEL > 0) PSEL--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t ship_live = 0, ship_dead = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i].ctr >= 2) ship_live++; else ship_dead++;
    std::cout << "DSS: live sigs=" << ship_live
              << ", dead sigs=" << ship_dead
              << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed; all counters saturating.
}