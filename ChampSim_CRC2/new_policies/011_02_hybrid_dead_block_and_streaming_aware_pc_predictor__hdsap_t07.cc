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

// Dead-block predictor: 2 bits/block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits/block

// Streaming detector: per-set, last addr/delta, 1-bit flag, 3-bit confidence
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_flag[LLC_SETS]; // 1 bit/set
uint8_t stream_conf[LLC_SETS];    // 3 bits/set

// PC reuse filter: 4-bit signature/block, global table 32 entries x 2 bits
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 4 bits/block
uint8_t pc_table[32]; // 2 bits/entry

// SRRIP/BRRIP set-dueling: 64 leader sets, 10-bit PSEL
const uint32_t NUM_LEADER_SETS = 64;
const uint32_t LEADER_SETS_SRRIP = 32;
const uint32_t LEADER_SETS_BRRIP = 32;
bool is_leader_set_srrip[LLC_SETS];
bool is_leader_set_brrip[LLC_SETS];
uint16_t PSEL = 512; // 10 bits, mid-value

// Helper: hash PC to 4 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 7) ^ (PC >> 13)) & 0x1F;
}

// Assign leader sets for SRRIP/BRRIP
void AssignLeaderSets() {
    memset(is_leader_set_srrip, 0, sizeof(is_leader_set_srrip));
    memset(is_leader_set_brrip, 0, sizeof(is_leader_set_brrip));
    for (uint32_t i = 0; i < LEADER_SETS_SRRIP; ++i)
        is_leader_set_srrip[(i * LLC_SETS) / NUM_LEADER_SETS] = true;
    for (uint32_t i = 0; i < LEADER_SETS_BRRIP; ++i)
        is_leader_set_brrip[(i * LLC_SETS) / NUM_LEADER_SETS + 1] = true;
}

// --- Periodic counter decay for dead-block predictor ---
void DecayDeadCounters() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] > 0)
                dead_ctr[set][way]--;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_ctr, 1, sizeof(dead_ctr));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(pc_table, 1, sizeof(pc_table)); // weakly reused
    PSEL = 512; // midpoint
    AssignLeaderSets();
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(stream_conf, 0, sizeof(stream_conf));
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
    // Streaming: prefer block with RRPV==3
    if (streaming_flag[set]) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment RRPV until found
        while (true) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] == 3)
                    return way;
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] < 3)
                    rrpv[set][way]++;
        }
    }

    // Dead-block: prefer block whose dead_ctr==0 and RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 0 && rrpv[set][way] == 3)
            return way;

    // RRIP fallback: pick block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
    // Increment RRPV until found
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
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
    // --- Streaming detector update ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_conf[set] < 7) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    last_addr[set] = paddr;
    last_delta[set] = delta;
    streaming_flag[set] = (stream_conf[set] >= 5) ? 1 : 0;

    // --- PC signature ---
    uint8_t sig = pc_hash(PC);

    // --- Set-dueling: choose SRRIP or BRRIP ---
    bool use_srrip = false, use_brrip = false;
    if (is_leader_set_srrip[set]) use_srrip = true;
    else if (is_leader_set_brrip[set]) use_brrip = true;
    else use_srrip = (PSEL >= 512);

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        dead_ctr[set][way] = 3; // High reuse
        if (pc_table[pc_sig[set][way]] < 3) pc_table[pc_sig[set][way]]++; // PC reuse up
        // PSEL: hits in leader sets
        if (is_leader_set_srrip[set] && PSEL < 1023) PSEL++;
        if (is_leader_set_brrip[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- On cache miss or fill ---
    uint8_t ins_rrpv;
    if (streaming_flag[set]) {
        // Streaming: insert at LRU (RRIP=3) to quickly evict
        ins_rrpv = 3;
    } else if (use_srrip) {
        ins_rrpv = 2; // SRRIP default (long re-reference interval)
    } else if (use_brrip) {
        // BRRIP: Insert at RRIP=2 most of time, RRIP=3 rarely (1/32)
        static uint32_t br_counter = 0;
        if ((br_counter++ % 32) == 0)
            ins_rrpv = 3;
        else
            ins_rrpv = 2;
    } else {
        // Dynamic: use PSEL winner
        ins_rrpv = (PSEL >= 512) ? 2 : 3;
    }

    // Dead-block predictor: if dead_ctr == 0, use LRU insertion
    if (dead_ctr[set][way] == 0)
        ins_rrpv = 3;

    // PC reuse filter: if PC shows frequent reuse, insert at MRU
    if (pc_table[sig] >= 2)
        ins_rrpv = 0;

    // Update block metadata
    pc_sig[set][way] = sig;
    rrpv[set][way] = ins_rrpv;
    dead_ctr[set][way] = 1; // weakly reused on insertion
    if (pc_table[sig] > 0) pc_table[sig]--; // decay PC reuse on fill

    // PSEL: misses in leader sets
    if (is_leader_set_srrip[set] && PSEL > 0) PSEL--;
    if (is_leader_set_brrip[set] && PSEL < 1023) PSEL++;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s])
            streaming_sets++;
    std::cout << "HDSAP: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // Dead-block summary
    uint64_t dead_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] == 0)
                dead_lines++;
    std::cout << "HDSAP: Dead lines at end: " << dead_lines << " / " << (LLC_SETS * LLC_WAYS) << std::endl;

    // PC reuse table
    std::cout << "HDSAP: PC table (reuse counters): ";
    for (int i = 0; i < 32; ++i)
        std::cout << (int)pc_table[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "HDSAP: SRRIP/BRRIP PSEL = " << (int)PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    static uint64_t ticks = 0;
    if ((++ticks % 5000000) == 0)
        DecayDeadCounters();
}