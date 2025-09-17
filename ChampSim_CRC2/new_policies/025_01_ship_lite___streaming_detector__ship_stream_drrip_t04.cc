#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signatures, 2-bit outcome counters ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
struct SHIPEntry {
    uint8_t ctr; // 2 bits: saturating counter
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// Per-block metadata: RRPV + PC signature
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t sig;       // 6 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// --- Streaming Detector: per-set last address, stride, streaming count ---
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_stride;
    uint8_t stream_count; // 2 bits
};
StreamDetect stream_info[LLC_SETS];

// --- DRRIP: 64 leader sets for SRRIP, 64 for BRRIP ---
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
    memset(ship_table, 0, sizeof(ship_table));
    memset(meta, 0, sizeof(meta));
    memset(stream_info, 0, sizeof(stream_info));
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
    // --- SHiP signature ---
    uint8_t sig = (PC ^ (PC >> 8) ^ (PC >> 16)) & ((1 << SHIP_SIG_BITS) - 1);

    // --- Streaming Detector ---
    StreamDetect &sd = stream_info[set];
    int64_t stride = paddr - sd.last_addr;
    bool streaming = false;
    if (sd.stream_count >= 2 && stride == sd.last_stride && stride != 0) {
        streaming = true;
    }
    // Update streaming info
    if (stride == sd.last_stride && stride != 0) {
        if (sd.stream_count < 3) sd.stream_count++;
    } else {
        sd.stream_count = 0;
        sd.last_stride = stride;
    }
    sd.last_addr = paddr;

    // --- SHiP update on hit ---
    if (hit) {
        meta[set][way].rrpv = 0; // promote to MRU
        // Update SHiP table: increment counter for signature
        if (ship_table[sig].ctr < 3) ship_table[sig].ctr++;
        // DRRIP update for leader sets
        bool is_leader_srrip = false, is_leader_brrip = false;
        for (auto s : leader_srrip) if (set == s) is_leader_srrip = true;
        for (auto s : leader_brrip)  if (set == s) is_leader_brrip = true;
        if (is_leader_srrip && PSEL < 1023) PSEL++;
        if (is_leader_brrip && PSEL > 0) PSEL--;
        return;
    }

    // --- SHiP update on eviction: decrement outcome counter for evicted block's signature ---
    uint8_t victim_sig = meta[set][way].sig;
    if (ship_table[victim_sig].ctr > 0) ship_table[victim_sig].ctr--;

    // --- DRRIP set-dueling: choose insertion policy ---
    bool is_leader_srrip = false, is_leader_brrip = false;
    for (auto s : leader_srrip) if (set == s) is_leader_srrip = true;
    for (auto s : leader_brrip)  if (set == s) is_leader_brrip = true;

    uint8_t ins_rrpv = 3; // default distant

    // --- Streaming detector: if streaming, force distant insertion ---
    if (streaming) {
        ins_rrpv = 3;
    } else {
        // --- SHiP: use outcome counter for signature ---
        uint8_t ship_ctr = ship_table[sig].ctr;
        if (ship_ctr >= 2)
            ins_rrpv = 2; // likely reused
        else
            ins_rrpv = 3; // likely dead
    }

    // --- Leader sets override insertion ---
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

    // --- On fill: set insertion RRPV, record signature ---
    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].sig = sig;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t reused = 0, dead = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].ctr >= 2) reused++; else dead++;
    std::cout << "SHiP-Stream-DRRIP: SHiP reused sigs=" << reused << ", dead sigs=" << dead << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed; streaming detector is self-resetting.
}