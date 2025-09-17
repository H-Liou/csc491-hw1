#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023

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

// DRRIP PSEL selector
uint16_t PSEL = PSEL_MAX / 2;

// Leader sets for SRRIP and BRRIP
std::vector<uint32_t> leader_srrip;
std::vector<uint32_t> leader_brrip;

// Helper: assign leader sets
void InitLeaderSets() {
    leader_srrip.clear();
    leader_brrip.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_srrip.push_back(i); // first 64 sets
        leader_brrip.push_back(LLC_SETS - 1 - i); // last 64 sets
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(ship_table, 0, sizeof(ship_table));
    memset(stream_meta, 0, sizeof(stream_meta));
    PSEL = PSEL_MAX / 2;
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

    // --- On hit: update SHiP outcome, promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        if (ship_table[sig].ctr < 3) ship_table[sig].ctr++;
        return;
    }

    // --- Streaming bypass: DIP-style ---
    bool streaming = (sd.stream_cnt >= 4);
    if (streaming) {
        // Streaming detected: bypass fill (simulate by marking block as invalid)
        meta[set][way].rrpv = 3;
        meta[set][way].sig = sig;
        return;
    }

    // --- DRRIP set-dueling for insertion depth ---
    bool is_leader_srrip = (std::find(leader_srrip.begin(), leader_srrip.end(), set) != leader_srrip.end());
    bool is_leader_brrip = (std::find(leader_brrip.begin(), leader_brrip.end(), set) != leader_brrip.end());

    uint8_t ins_rrpv = 2; // SRRIP default
    if (is_leader_srrip) {
        ins_rrpv = 2; // always SRRIP
    } else if (is_leader_brrip) {
        ins_rrpv = 3; // always BRRIP
    } else {
        // Use PSEL to choose
        if (PSEL >= (PSEL_MAX / 2))
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = 3; // BRRIP
    }

    // --- SHiP-lite bias: if high reuse, insert at SRRIP ---
    uint8_t ship_conf = ship_table[sig].ctr;
    if (ship_conf >= 2)
        ins_rrpv = 2; // promote to SRRIP

    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].sig = sig;

    // --- DRRIP PSEL update on leader sets ---
    if (is_leader_srrip) {
        if (hit && PSEL < PSEL_MAX) PSEL++;
    } else if (is_leader_brrip) {
        if (hit && PSEL > 0) PSEL--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t ship_live = 0, ship_dead = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i].ctr >= 2) ship_live++; else ship_dead++;
    std::cout << "DRRIP+SHiP+DIP-Stream: live sigs=" << ship_live
              << ", dead sigs=" << ship_dead
              << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed for this policy
}