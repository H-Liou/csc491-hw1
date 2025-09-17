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

// Streaming detector: per-set last address, stride, stream count (3 bits)
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_stride;
    uint8_t stream_cnt; // 3 bits
};
StreamDetect stream_meta[LLC_SETS];

// Periodic decay: heartbeat counter
uint64_t heartbeat = 0;

// Helper: assign leader sets for statistics (optional)
std::vector<uint32_t> leader_sets;
void InitLeaderSets() {
    leader_sets.clear();
    for (uint32_t i = 0; i < 64; ++i)
        leader_sets.push_back(i);
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(ship_table, 0, sizeof(ship_table));
    memset(stream_meta, 0, sizeof(stream_meta));
    heartbeat = 0;
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

    // --- On hit: update SHiP and dead-block counter, promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        meta[set][way].dead_ctr = 0; // block reused, reset dead counter
        if (ship_table[sig].ctr < 3) ship_table[sig].ctr++;
        return;
    }

    // --- On fill: streaming bypass ---
    if (sd.stream_cnt >= 4) {
        // Streaming detected: bypass fill (simulate by marking block as invalid)
        meta[set][way].rrpv = 3;
        meta[set][way].dead_ctr = 3; // treat as dead
        meta[set][way].sig = sig;
        // Decay SHiP counter for victim
        uint16_t victim_sig = meta[set][way].sig;
        if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;
        return;
    }

    // --- On fill: combine SHiP and dead-block counter for insertion ---
    meta[set][way].sig = sig;
    uint8_t ship_conf = ship_table[sig].ctr;
    uint8_t dead_conf = meta[set][way].dead_ctr;

    uint8_t ins_rrpv = 3; // default distant
    if (ship_conf >= 2 && dead_conf <= 1)
        ins_rrpv = 2; // likely to be reused, insert at SRRIP
    else
        ins_rrpv = 3; // likely dead or low reuse, insert at distant

    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].dead_ctr = 0; // new block, start as not dead

    // Decay SHiP counter for victim
    uint16_t victim_sig = meta[set][way].sig;
    if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;
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
    std::cout << "SHiP+Dead+Stream: live sigs=" << ship_live
              << ", dead sigs=" << ship_dead
              << ", dead blocks=" << dead_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay of dead-block counters (every 100K accesses)
    heartbeat++;
    if (heartbeat % 100000 == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (meta[s][w].dead_ctr > 0)
                    meta[s][w].dead_ctr--;
    }
}