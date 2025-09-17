#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per-block, 10-bit PSEL global, 32 leader sets
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // Middle value

// DRRIP leader sets (first 32 sets for SRRIP, next 32 for BRRIP)
std::vector<uint32_t> sr_leader_sets, br_leader_sets;
// DIP-style streaming bypass leader sets (next 32 sets)
std::vector<uint32_t> stream_leader_sets;

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

// Helper: assign leader sets for DRRIP and streaming
void InitLeaderSets() {
    sr_leader_sets.clear();
    br_leader_sets.clear();
    stream_leader_sets.clear();
    for (uint32_t i = 0; i < 32; ++i) {
        sr_leader_sets.push_back(i);
        br_leader_sets.push_back(i + 32);
        stream_leader_sets.push_back(i + 64);
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(ship_table, 0, sizeof(ship_table));
    memset(stream_meta, 0, sizeof(stream_meta));
    PSEL = (1 << (PSEL_BITS - 1));
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
        // Streaming detected: bypass fill (simulate by marking block as invalid)
        meta[set][way].rrpv = 3;
        meta[set][way].sig = sig;
        // Decay SHiP counter for victim
        uint16_t victim_sig = meta[set][way].sig;
        if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;
        return;
    }

    // --- DRRIP insertion depth selection ---
    uint8_t ins_rrpv = 3; // default distant
    bool is_sr_leader = false, is_br_leader = false;
    for (int i = 0; i < 32; ++i) {
        if (set == sr_leader_sets[i]) is_sr_leader = true;
        if (set == br_leader_sets[i]) is_br_leader = true;
    }
    if (is_sr_leader)
        ins_rrpv = 2; // SRRIP
    else if (is_br_leader)
        ins_rrpv = 3; // BRRIP
    else
        ins_rrpv = ((PSEL >= (1 << (PSEL_BITS - 1))) ? 2 : 3);

    // --- SHiP-lite: boost insertion if signature is reused ---
    uint8_t ship_conf = ship_table[sig].ctr;
    if (ship_conf >= 2)
        ins_rrpv = 1; // very likely reused

    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].sig = sig;

    // --- Update DRRIP PSEL on leader sets ---
    if (is_sr_leader && !hit) {
        if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    }
    if (is_br_leader && !hit) {
        if (PSEL > 0) PSEL--;
    }

    // --- Decay SHiP counter for victim ---
    uint16_t victim_sig = meta[set][way].sig;
    if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;
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
    // No periodic decay needed; all counters saturate naturally.
}