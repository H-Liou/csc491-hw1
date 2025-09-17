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
    uint8_t sig;       // 6 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// SHiP-lite: 6-bit PC signature table, 2-bit outcome counter
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024
struct ShipEntry {
    uint8_t ctr; // 2 bits
};
ShipEntry ship_table[SHIP_SIG_ENTRIES];

// DRRIP: 10-bit PSEL, 64 leader sets for SRRIP/BRRIP, 32 for streaming bypass
uint16_t PSEL = 512;
std::vector<uint32_t> sr_leader_sets;
std::vector<uint32_t> br_leader_sets;
std::vector<uint32_t> stream_leader_sets;

// Streaming detector: per-set last address, stride, stream count (3 bits)
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_stride;
    uint8_t stream_cnt; // 3 bits
};
StreamDetect stream_meta[LLC_SETS];

// Helper: assign leader sets for DRRIP and streaming
void InitLeaderSets() {
    sr_leader_sets.clear();
    br_leader_sets.clear();
    stream_leader_sets.clear();
    for (uint32_t i = 0; i < 64; ++i) {
        sr_leader_sets.push_back(i);
        br_leader_sets.push_back(LLC_SETS/2 + i);
    }
    for (uint32_t i = 0; i < 32; ++i)
        stream_leader_sets.push_back(LLC_SETS/4 + i);
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(ship_table, 0, sizeof(ship_table));
    memset(stream_meta, 0, sizeof(stream_meta));
    PSEL = 512;
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

    // --- On hit: update SHiP and promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        if (ship_table[sig].ctr < 3) ship_table[sig].ctr++;
        return;
    }

    // --- Streaming leader sets: streaming bypass logic ---
    bool is_stream_leader = std::find(stream_leader_sets.begin(), stream_leader_sets.end(), set) != stream_leader_sets.end();
    bool streaming_now = (sd.stream_cnt >= 4);

    // --- DRRIP leader sets: insertion policy selection ---
    bool is_sr_leader = std::find(sr_leader_sets.begin(), sr_leader_sets.end(), set) != sr_leader_sets.end();
    bool is_br_leader = std::find(br_leader_sets.begin(), br_leader_sets.end(), set) != br_leader_sets.end();

    // --- Determine insertion depth ---
    uint8_t ins_rrpv = 3; // default distant

    if (is_stream_leader && streaming_now) {
        // Streaming detected in leader set: bypass fill (simulate by marking block as distant)
        ins_rrpv = 3;
        // Adjust PSEL to favor streaming bypass
        if (PSEL < 1023) PSEL++;
    } else if (is_sr_leader) {
        // SRRIP leader: always insert at RRPV=2
        ins_rrpv = 2;
        // If hit, decrease PSEL (SRRIP is good)
        if (hit && PSEL > 0) PSEL--;
    } else if (is_br_leader) {
        // BRRIP leader: insert at RRPV=3 with low probability (1/32)
        ins_rrpv = ((rand() % 32) == 0) ? 2 : 3;
        // If hit, increase PSEL (BRRIP is good)
        if (hit && PSEL < 1023) PSEL++;
    } else {
        // Follower sets: choose SRRIP or BRRIP based on PSEL
        if (PSEL < 512)
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = ((rand() % 32) == 0) ? 2 : 3; // BRRIP
    }

    // --- SHiP-lite: bias insertion for high-reuse signatures ---
    uint8_t ship_conf = ship_table[sig].ctr;
    if (ship_conf >= 2 && !streaming_now)
        ins_rrpv = 0; // insert at MRU if signature is highly reused

    // --- Fill block metadata ---
    meta[set][way].sig = sig;
    meta[set][way].rrpv = ins_rrpv;

    // --- Decay SHiP counter for victim ---
    uint16_t victim_sig = meta[set][way].sig;
    if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t ship_live = 0, ship_dead = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i].ctr >= 2) ship_live++; else ship_dead++;
    std::cout << "DRRIP+SHiP+Stream: live sigs=" << ship_live
              << ", dead sigs=" << ship_dead
              << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed for this policy
}