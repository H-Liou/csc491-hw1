#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per line
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 8 KiB

// DRRIP: set-dueling leader sets (32 SRRIP, 32 BRRIP)
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // midpoint
bool is_sr_leader[LLC_SETS]; // 2 KiB
bool is_br_leader[LLC_SETS]; // 2 KiB

// Streaming detector: per-set last addr/delta, 1-bit flag, 3-bit confidence
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_flag[LLC_SETS]; // 1 bit/set
uint8_t stream_conf[LLC_SETS];    // 3 bits/set

// Helper: hash set index to leader sets
inline void InitLeaderSets() {
    memset(is_sr_leader, 0, sizeof(is_sr_leader));
    memset(is_br_leader, 0, sizeof(is_br_leader));
    // Use first 32 sets as SRRIP leaders, next 32 as BRRIP leaders
    for (uint32_t i = 0; i < 32; ++i)
        is_sr_leader[i] = true;
    for (uint32_t i = 32; i < 64; ++i)
        is_br_leader[i] = true;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU on reset
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(stream_conf, 0, sizeof(stream_conf));
    InitLeaderSets();
    PSEL = (1 << (PSEL_BITS - 1)); // midpoint
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
    // Streaming: prefer bypass (find invalid, otherwise LRU)
    if (streaming_flag[set]) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        while (true) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] == 3)
                    return way;
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (rrpv[set][way] < 3)
                    rrpv[set][way]++;
        }
    }
    // RRIP: pick block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0;
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

    // --- DRRIP insertion depth control ---
    uint8_t ins_rrpv = 3; // default LRU

    if (streaming_flag[set]) {
        ins_rrpv = 3; // streaming: insert at LRU (simulate bypass)
    }
    else if (is_sr_leader[set]) {
        ins_rrpv = 2; // SRRIP: insert at RRPV=2 (longer retention)
    }
    else if (is_br_leader[set]) {
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at RRPV=2 very rarely (1/32)
    }
    else {
        // Follower sets: use PSEL
        if (PSEL >= (1 << (PSEL_BITS - 1)))
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
    }

    // On hit: promote to MRU
    if (hit) {
        rrpv[set][way] = 0;
        // Only leader sets update PSEL
        if (is_sr_leader[set]) {
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++; // SRRIP better
        }
        if (is_br_leader[set]) {
            if (PSEL > 0) PSEL--; // BRRIP better
        }
        return;
    }

    // On miss/fill: set RRPV
    rrpv[set][way] = ins_rrpv;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s])
            streaming_sets++;
    std::cout << "DRRIP-SA: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "DRRIP-SA: Final PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally decay stream confidence to avoid stuck streaming
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_conf[s] > 0)
            stream_conf[s]--;
}