#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];  // 2 bits per block

// --- DRRIP Set-dueling: Leader sets and PSEL ---
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = 1 << (PSEL_BITS - 1); // start neutral
uint32_t leader_sets[NUM_LEADER_SETS]; // indices of leader sets

// --- Streaming detector: per-set recent address delta ---
int32_t last_addr[LLC_SETS];    // Last address seen in set
int32_t last_delta[LLC_SETS];   // Last delta
uint8_t stream_score[LLC_SETS]; // 8 bits per set

// Helper: initialize leader sets (spread evenly)
void InitLeaderSets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        leader_sets[i] = (i * LLC_SETS) / NUM_LEADER_SETS;
}

bool is_leader_set(uint32_t set, bool sr) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS/2; ++i)
        if (sr && set == leader_sets[i]) return true;
    for (uint32_t i = NUM_LEADER_SETS/2; i < NUM_LEADER_SETS; ++i)
        if (!sr && set == leader_sets[i]) return true;
    return false;
}

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way] = 3; // distant
    InitLeaderSets();
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_score, 0, sizeof(stream_score));
    psel = 1 << (PSEL_BITS-1);
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
    // Streaming bypass: if stream_score high, bypass (return LLC_WAYS)
    if (stream_score[set] >= 8)
        return LLC_WAYS; // convention: bypass, don't insert

    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Classic RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
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
    int32_t addr = (int32_t)(paddr >> 6); // block address
    int32_t delta = addr - last_addr[set];
    if (last_addr[set] != 0) {
        if (delta == last_delta[set] && delta != 0) {
            if (stream_score[set] < 15) stream_score[set]++;
        } else {
            if (stream_score[set] > 0) stream_score[set]--;
        }
    }
    last_delta[set] = delta;
    last_addr[set] = addr;

    // --- DRRIP insertion policy ---
    // If streaming detected, bypass: do not insert
    if (stream_score[set] >= 8)
        return;

    // Determine if this is a leader set (SRRIP or BRRIP group)
    bool is_srrip_leader = is_leader_set(set, true);
    bool is_brrip_leader = is_leader_set(set, false);

    // Choose policy for non-leader sets
    bool use_brrip = (psel < (1 << (PSEL_BITS-1)));
    uint8_t insert_rrpv = 2; // Default SRRIP: RRPV=2
    if ((is_brrip_leader) || (!is_srrip_leader && use_brrip)) {
        // BRRIP: Insert at distant (RRPV=3) with high probability, MRU (0) rarely
        insert_rrpv = (rand() % 32 == 0) ? 0 : 3; // 1/32 chance of MRU, else distant
    }

    // On hit, promote to MRU
    if (hit)
        rrpv[set][way] = 0;
    else
        rrpv[set][way] = insert_rrpv;

    // --- Update PSEL on leader sets ---
    if (is_srrip_leader && !hit && psel < ((1 << PSEL_BITS) - 1)) psel++;
    if (is_brrip_leader && !hit && psel > 0) psel--;

}

// Print end-of-simulation statistics
void PrintStats() {
    int distant_blocks = 0, mru_blocks = 0, bypass_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (stream_score[set] >= 8) bypass_sets++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3) distant_blocks++;
            if (rrpv[set][way] == 0) mru_blocks++;
        }
    }
    std::cout << "DRRIP + Adaptive Streaming Bypass (DASB)" << std::endl;
    std::cout << "MRU blocks: " << mru_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Bypass sets (streaming detected): " << bypass_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int mru_blocks = 0, bypass_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (stream_score[set] >= 8) bypass_sets++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 0) mru_blocks++;
    }
    std::cout << "MRU blocks (heartbeat): " << mru_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Bypass sets (stream): " << bypass_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL: " << psel << std::endl;
}