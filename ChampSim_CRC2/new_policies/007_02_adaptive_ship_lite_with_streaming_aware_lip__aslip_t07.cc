#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 4-bit PC signature per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS];      // 4 bits/block

// SHiP-lite: 16-entry outcome table (indexed by signature)
uint8_t ship_table[16]; // 2 bits per entry

// DIP: 8-bit PSEL
uint8_t PSEL = 128; // 8 bits, mid-value

// DIP: 32 leader sets each for SHiP-based and pure LIP
const uint32_t NUM_LEADER_SETS = 64;
const uint32_t LEADER_SETS_SHIP = 32;
const uint32_t LEADER_SETS_LIP = 32;
bool is_leader_set_ship[LLC_SETS];
bool is_leader_set_lip[LLC_SETS];

// Streaming detector: 3 bits/set
struct StreamSet {
    uint64_t last_addr;
    uint8_t stride_count; // up to 3
    uint8_t streaming;    // 1 if streaming detected
    uint8_t window;       // streaming window countdown
};
StreamSet stream_sets[LLC_SETS];

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_LRU = 3;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// Helper: hash PC to 4 bits
inline uint8_t pc_hash(uint64_t PC) {
    return ((PC ^ (PC >> 4) ^ (PC >> 8)) & 0xF);
}

// Assign leader sets for DIP
void AssignLeaderSets() {
    memset(is_leader_set_ship, 0, sizeof(is_leader_set_ship));
    memset(is_leader_set_lip, 0, sizeof(is_leader_set_lip));
    for (uint32_t i = 0; i < LEADER_SETS_SHIP; ++i)
        is_leader_set_ship[(i * LLC_SETS) / NUM_LEADER_SETS] = true;
    for (uint32_t i = 0; i < LEADER_SETS_LIP; ++i)
        is_leader_set_lip[(i * LLC_SETS) / NUM_LEADER_SETS + 1] = true;
}

void InitReplacementState() {
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    memset(stream_sets, 0, sizeof(stream_sets));
    PSEL = 128; // midpoint
    AssignLeaderSets();
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming: if active, always insert at LRU, so seek block with RRPV==RRIP_MAX
    if (stream_sets[set].streaming && stream_sets[set].window > 0) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        // Increment RRPV and retry
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < RRIP_MAX)
                rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        return 0;
    }

    // Normal: RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] < RRIP_MAX)
            rrpv[set][way]++;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    return 0;
}

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
    // --- Streaming detector ---
    StreamSet &ss = stream_sets[set];
    uint64_t cur_addr = paddr >> 6; // cache line granularity
    int64_t stride = cur_addr - ss.last_addr;
    if (ss.last_addr != 0 && (stride == 1 || stride == -1)) {
        if (ss.stride_count < 3) ss.stride_count++;
        if (ss.stride_count == 3 && !ss.streaming) {
            ss.streaming = 1;
            ss.window = STREAM_WIN;
        }
    } else {
        ss.stride_count = 0;
        ss.streaming = 0;
        ss.window = 0;
    }
    ss.last_addr = cur_addr;
    if (ss.streaming && ss.window > 0)
        ss.window--;

    // --- SHiP-lite signature ---
    uint8_t sig = pc_hash(PC);

    // --- DIP insertion policy selection ---
    bool use_ship = false, use_lip = false;
    if (is_leader_set_ship[set]) use_ship = true;
    else if (is_leader_set_lip[set]) use_lip = true;
    else use_ship = (PSEL >= 128);

    // Streaming detected: always insert at LRU (LIP), no SHiP update
    if (ss.streaming && ss.window > 0) {
        if (hit) {
            rrpv[set][way] = RRIP_MRU;
        } else {
            rrpv[set][way] = RRIP_LRU;
            pc_sig[set][way] = sig;
        }
        // DIP: update PSEL for leader sets
        if (is_leader_set_ship[set] && hit && PSEL < 255) PSEL++;
        if (is_leader_set_ship[set] && !hit && PSEL > 0) PSEL--;
        if (is_leader_set_lip[set] && hit && PSEL > 0) PSEL--;
        if (is_leader_set_lip[set] && !hit && PSEL < 255) PSEL++;
        return;
    }

    // SHiP outcome prediction for insertion
    uint8_t pred = ship_table[sig];
    uint8_t ins_rrpv = (pred >= 2) ? RRIP_MRU : RRIP_LRU;

    if (use_lip) ins_rrpv = RRIP_LRU;
    // If use_ship, use ins_rrpv as above

    if (hit) {
        rrpv[set][way] = RRIP_MRU;
        // Update SHiP outcome
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
        // DIP: update PSEL for leader sets
        if (is_leader_set_ship[set] && PSEL < 255) PSEL++;
        if (is_leader_set_lip[set] && PSEL > 0) PSEL--;
    } else {
        // On insertion, set signature and RRPV
        pc_sig[set][way] = sig;
        rrpv[set][way] = ins_rrpv;
        // SHiP outcome: weak initial prediction
        if (ship_table[sig] > 0) ship_table[sig]--;
        // DIP: update PSEL for leader sets
        if (is_leader_set_ship[set] && PSEL > 0) PSEL--;
        if (is_leader_set_lip[set] && PSEL < 255) PSEL++;
    }
}

void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "ASLIP: Streaming sets at end: " << streaming_sets << std::endl;

    // SHiP table summary
    std::cout << "ASLIP: SHiP table (reuse counters): ";
    for (int i = 0; i < 16; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "ASLIP: DIP PSEL = " << (int)PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print streaming set count or PSEL
}