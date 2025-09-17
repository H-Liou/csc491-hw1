#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t sig;       // 6 bits (for SHiP-lite)
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// DRRIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // initialize to midpoint
std::vector<uint32_t> sr_leader_sets, br_leader_sets;

// SHiP-lite: 6-bit PC signature table, 2-bit outcome counter
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024
struct ShipEntry {
    uint8_t ctr; // 2 bits
};
ShipEntry ship_table[SHIP_SIG_ENTRIES];

// Streaming detector: per-set last address, stride, stream count (3 bits)
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_stride;
    uint8_t stream_cnt; // 3 bits
    bool bypass;        // DIP-style: set-wide bypass mode
};
StreamDetect stream_meta[LLC_SETS];

// Initialize leader sets for DRRIP set-dueling
void InitLeaderSets() {
    sr_leader_sets.clear();
    br_leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        sr_leader_sets.push_back(i); // first 64 sets: SRRIP
        br_leader_sets.push_back(LLC_SETS - 1 - i); // last 64 sets: BRRIP
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
    // DIP-style: enter bypass mode if streaming detected for 4+ consecutive fills
    if (sd.stream_cnt >= 4) sd.bypass = true;
    else if (sd.stream_cnt == 0) sd.bypass = false;

    // --- On hit: update SHiP outcome counter, promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        if (ship_table[sig].ctr < 3) ship_table[sig].ctr++;
        return;
    }

    // --- On fill: streaming bypass ---
    if (sd.bypass) {
        // Streaming detected: bypass fill (simulate by marking block as invalid)
        meta[set][way].rrpv = 3;
        meta[set][way].sig = sig;
        // Decay SHiP counter for victim
        uint16_t victim_sig = meta[set][way].sig;
        if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;
        return;
    }

    // --- DRRIP set-dueling: choose insertion depth ---
    bool is_sr_leader = std::find(sr_leader_sets.begin(), sr_leader_sets.end(), set) != sr_leader_sets.end();
    bool is_br_leader = std::find(br_leader_sets.begin(), br_leader_sets.end(), set) != br_leader_sets.end();
    uint8_t ins_rrpv = 2; // default SRRIP
    if (is_sr_leader) ins_rrpv = 2; // always SRRIP
    else if (is_br_leader) ins_rrpv = 3; // always BRRIP
    else ins_rrpv = (PSEL >= (1 << (PSEL_BITS - 1))) ? 2 : 3; // select by PSEL

    // --- SHiP-lite: bias insertion depth for high-reuse signatures ---
    meta[set][way].sig = sig;
    uint8_t ship_conf = ship_table[sig].ctr;
    if (ship_conf >= 2) ins_rrpv = 2; // likely to be reused, insert at SRRIP

    meta[set][way].rrpv = ins_rrpv;

    // --- DRRIP set-dueling: update PSEL on leader sets ---
    if (is_sr_leader && !hit) {
        if (PSEL > 0) PSEL--;
    } else if (is_br_leader && hit) {
        if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    }

    // Decay SHiP counter for victim
    uint16_t victim_sig = meta[set][way].sig;
    if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t ship_live = 0, ship_dead = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i].ctr >= 2) ship_live++; else ship_dead++;
    uint32_t bypass_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].bypass) bypass_sets++;
    std::cout << "DRRIP+SHiP+DIP-stream: live sigs=" << ship_live
              << ", dead sigs=" << ship_dead
              << ", bypass sets=" << bypass_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed; SHiP counters decay on replacement
}