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

// SHiP-lite: 64-entry outcome table (indexed by signature), 2 bits/entry
uint8_t ship_table[64]; // 2 bits per entry

// DRRIP: 10-bit PSEL
uint16_t PSEL = 512; // 10 bits, mid-value

// DRRIP: 64 leader sets (32 SRRIP, 32 BRRIP)
const uint32_t NUM_LEADER_SETS = 64;
const uint32_t LEADER_SETS_SRRIP = 32;
const uint32_t LEADER_SETS_BRRIP = 32;
bool is_leader_set_srrip[LLC_SETS];
bool is_leader_set_brrip[LLC_SETS];

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

// BRRIP insertion: insert at distant (RRIP_MAX) only 1/32, else at near-MRU (RRIP_MRU+1)
uint32_t BRRIP_DISTANT_interval = 32;
uint32_t brrip_insertion_counter = 0;

// Helper: hash PC to 6 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Assign leader sets for DRRIP
void AssignLeaderSets() {
    memset(is_leader_set_srrip, 0, sizeof(is_leader_set_srrip));
    memset(is_leader_set_brrip, 0, sizeof(is_leader_set_brrip));
    for (uint32_t i = 0; i < LEADER_SETS_SRRIP; ++i)
        is_leader_set_srrip[(i * LLC_SETS) / NUM_LEADER_SETS] = true;
    for (uint32_t i = 0; i < LEADER_SETS_BRRIP; ++i)
        is_leader_set_brrip[(i * LLC_SETS) / NUM_LEADER_SETS + 1] = true;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    memset(stream_sets, 0, sizeof(stream_sets));
    PSEL = 512; // midpoint
    AssignLeaderSets();
}

// Find victim in the set
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
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < RRIP_MAX)
                rrpv[set][way]++;
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

    // --- DRRIP insertion policy selection ---
    bool use_srrip = false, use_brrip = false;
    if (is_leader_set_srrip[set]) use_srrip = true;
    else if (is_leader_set_brrip[set]) use_brrip = true;
    else use_srrip = (PSEL >= 512);

    // Streaming detected: bypass insertion unless SHiP predicts high reuse
    bool streaming_active = (ss.streaming && ss.window > 0);
    uint8_t ship_pred = ship_table[sig];

    bool do_bypass = false;
    if (streaming_active && ship_pred < 2) // not likely to be reused
        do_bypass = true;

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = RRIP_MRU;
        // Update SHiP outcome
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
        // DRRIP: On hit in leader sets, increment PSEL for SRRIP, decrement for BRRIP
        if (is_leader_set_srrip[set] && PSEL < 1023) PSEL++;
        if (is_leader_set_brrip[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- On cache miss or fill ---
    if (do_bypass) {
        // Bypass: do not allocate line, so no updates to rrpv/pc_sig
        // Only update SHiP and PSEL
        if (ship_table[sig] > 0) ship_table[sig]--;
        if (is_leader_set_srrip[set] && PSEL > 0) PSEL--;
        if (is_leader_set_brrip[set] && PSEL < 1023) PSEL++;
        return;
    }

    // Choose insertion RRPV
    uint8_t ins_rrpv;
    if (use_srrip) {
        ins_rrpv = RRIP_DISTANT;
    } else if (use_brrip) {
        // BRRIP: insert at RRIP_MAX only every 1/32, else at RRIP_DISTANT
        if ((brrip_insertion_counter++ % BRRIP_DISTANT_interval) == 0)
            ins_rrpv = RRIP_MAX;
        else
            ins_rrpv = RRIP_DISTANT;
    } else {
        // Dynamic: use PSEL winner
        ins_rrpv = (PSEL >= 512) ? RRIP_DISTANT : RRIP_MAX;
    }

    // SHiP bias: if PC signature is frequently reused, insert at MRU
    if (ship_pred >= 2)
        ins_rrpv = RRIP_MRU;

    // Update block metadata
    pc_sig[set][way] = sig;
    rrpv[set][way] = ins_rrpv;
    // SHiP outcome: weak initial prediction
    if (ship_table[sig] > 0) ship_table[sig]--;
    // DRRIP: On miss in leader sets, decrement PSEL for SRRIP, increment for BRRIP
    if (is_leader_set_srrip[set] && PSEL > 0) PSEL--;
    if (is_leader_set_brrip[set] && PSEL < 1023) PSEL++;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "SDSB: Streaming sets at end: " << streaming_sets << std::endl;

    // SHiP table summary
    std::cout << "SDSB: SHiP table (reuse counters): ";
    for (int i = 0; i < 64; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "SDSB: DRRIP PSEL = " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count or PSEL
}