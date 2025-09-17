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

// SHiP-lite: 6-bit PC signature per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS];      // 6 bits/block

// SHiP-lite: 64-entry outcome table (indexed by signature)
uint8_t ship_table[64]; // 2 bits per entry

// DIP: 10-bit PSEL
uint16_t PSEL = 512; // 10 bits, mid-value

// DIP: 64 leader sets (32 LIP, 32 BIP)
const uint32_t NUM_LEADER_SETS = 64;
const uint32_t LEADER_SETS_LIP = 32;
const uint32_t LEADER_SETS_BIP = 32;
bool is_leader_set_lip[LLC_SETS];
bool is_leader_set_bip[LLC_SETS];

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
const uint8_t RRIP_DISTANT = 2;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// BIP insertion: insert at LRU only every 1/32, else at MRU
uint32_t BIP_LRU_interval = 32;
uint32_t bip_insertion_counter = 0;

// Helper: hash PC to 6 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Assign leader sets for DIP
void AssignLeaderSets() {
    memset(is_leader_set_lip, 0, sizeof(is_leader_set_lip));
    memset(is_leader_set_bip, 0, sizeof(is_leader_set_bip));
    // Evenly distribute leader sets
    for (uint32_t i = 0; i < LEADER_SETS_LIP; ++i)
        is_leader_set_lip[(i * LLC_SETS) / NUM_LEADER_SETS] = true;
    for (uint32_t i = 0; i < LEADER_SETS_BIP; ++i)
        is_leader_set_bip[(i * LLC_SETS) / NUM_LEADER_SETS + 1] = true;
}

void InitReplacementState() {
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    memset(stream_sets, 0, sizeof(stream_sets));
    PSEL = 512; // midpoint
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
    // Dead-block: prefer blocks with RRPV==RRIP_MAX
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    // If none, increment RRPV and retry
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
    bool use_lip = false, use_bip = false;
    if (is_leader_set_lip[set]) use_lip = true;
    else if (is_leader_set_bip[set]) use_bip = true;
    else use_lip = (PSEL >= 512);

    // Streaming detected: insert at LRU (max RRPV) for window
    bool streaming_active = (ss.streaming && ss.window > 0);

    // SHiP outcome prediction for insertion
    uint8_t pred = ship_table[sig];
    uint8_t ins_rrpv;
    if (streaming_active) {
        ins_rrpv = RRIP_MAX;
    } else if (use_lip) {
        // LIP: always insert at LRU (max RRPV)
        ins_rrpv = RRIP_MAX;
    } else if (use_bip) {
        // BIP: insert at LRU only every 1/32, else at MRU
        if ((bip_insertion_counter++ % BIP_LRU_interval) == 0)
            ins_rrpv = RRIP_MAX;
        else
            ins_rrpv = RRIP_MRU;
    } else {
        // Dynamic: use PSEL winner
        ins_rrpv = (PSEL >= 512) ? RRIP_MAX : RRIP_MRU;
    }

    // SHiP bias: if PC signature is frequently reused, insert at MRU
    if (!streaming_active && pred >= 2)
        ins_rrpv = RRIP_MRU;

    if (hit) {
        rrpv[set][way] = RRIP_MRU;
        // Update SHiP outcome
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
        // DIP: On hit in leader sets, increment PSEL for LIP, decrement for BIP
        if (is_leader_set_lip[set] && PSEL < 1023) PSEL++;
        if (is_leader_set_bip[set] && PSEL > 0) PSEL--;
    } else {
        // On insertion, set signature and RRPV
        pc_sig[set][way] = sig;
        rrpv[set][way] = ins_rrpv;
        // SHiP outcome: weak initial prediction
        if (ship_table[sig] > 0) ship_table[sig]--;
        // DIP: On miss in leader sets, decrement PSEL for LIP, increment for BIP
        if (is_leader_set_lip[set] && PSEL > 0) PSEL--;
        if (is_leader_set_bip[set] && PSEL < 1023) PSEL++;
    }
}

void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "SSLB: Streaming sets at end: " << streaming_sets << std::endl;

    // SHiP table summary
    std::cout << "SSLB: SHiP table (reuse counters): ";
    for (int i = 0; i < 64; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "SSLB: DIP PSEL = " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print streaming set count or PSEL
}