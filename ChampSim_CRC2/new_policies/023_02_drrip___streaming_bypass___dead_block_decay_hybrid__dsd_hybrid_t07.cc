#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block approximation: 1-bit per block ---
uint8_t dead_block[LLC_SETS][LLC_WAYS];

// --- Streaming detector: 2-bit per set, last address/delta per set ---
uint8_t stream_ctr[LLC_SETS];        // 2-bit saturating counter per set
uint64_t last_addr[LLC_SETS];        // last filled address per set
uint64_t last_delta[LLC_SETS];       // last observed delta per set

// --- DRRIP set-dueling: 32 leader sets, 10-bit PSEL ---
#define NUM_LEADER_SETS 32
#define PSEL_MAX 1023
uint16_t psel = PSEL_MAX / 2;        // 10-bit PSEL, init to mid
uint32_t leader_sets[NUM_LEADER_SETS]; // indices of leader sets

// --- Dead-block decay heartbeat ---
#define DECAY_HEARTBEAT 50000
uint64_t access_count = 0;

// --- Helper: initialize leader sets for DRRIP ---
void InitLeaderSets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        leader_sets[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_block, 0, sizeof(dead_block));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    InitLeaderSets();
    psel = PSEL_MAX / 2;
    access_count = 0;
}

// --- Find victim: SRRIP logic ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

// --- Update replacement state ---
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
    access_count++;

    // --- Streaming detector: update on fill (miss only) ---
    if (!hit) {
        uint64_t delta = (last_addr[set] == 0) ? 0 : (paddr - last_addr[set]);
        if (last_addr[set] != 0 && delta == last_delta[set] && delta != 0) {
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
        last_delta[set] = delta;
        last_addr[set] = paddr;
    }

    // --- Dead-block tracking: update on hit and on fill ---
    if (hit) {
        dead_block[set][way] = 0;   // Mark as not dead
        rrpv[set][way] = 0;         // MRU on hit
        return;
    }

    // --- DRRIP set-dueling: determine insertion policy ---
    bool is_leader_sr = false, is_leader_br = false;
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (set == leader_sets[i]) {
            if (i % 2 == 0) is_leader_sr = true;  // even: SRRIP
            else            is_leader_br = true;  // odd: BRRIP
            break;
        }
    }

    // --- Streaming sets: bypass or distant insert ---
    bool streaming = (stream_ctr[set] >= 2);

    // --- Dead-block: MRU insert if recently reused ---
    bool not_dead = (dead_block[set][way] == 0);

    uint8_t ins_rrpv = 3; // default distant

    // 1. Streaming detected: bypass (do not insert), if possible, else distant insert
    if (streaming) {
        // For LLC, we cannot bypass on misses (must insert), so insert at RRPV=3
        ins_rrpv = 3;
    }
    // 2. Dead-block not set: MRU insert
    else if (not_dead) {
        ins_rrpv = 0;
    }
    // 3. DRRIP: use SRRIP or BRRIP insertion for non-leader sets
    else if (is_leader_sr) {
        ins_rrpv = 2; // SRRIP: insert at RRPV=2
    }
    else if (is_leader_br) {
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at RRPV=2 with low probability
    }
    else {
        // Non-leader sets: choose by PSEL
        if (psel >= (PSEL_MAX / 2)) {
            ins_rrpv = 2; // SRRIP
        } else {
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
        }
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    dead_block[set][way] = 1; // Mark as dead until reuse

    // --- On eviction: update PSEL for leader sets ---
    // If this set is a leader, adjust PSEL based on hit
    if (is_leader_sr && hit) {
        if (psel < PSEL_MAX) psel++;
    }
    else if (is_leader_br && hit) {
        if (psel > 0) psel--;
    }

    // --- On eviction: dead-block counter stays (decay logic periodic) ---
    // (Decay handled in PrintStats_Heartbeat)
}

// --- Periodic dead-block decay ---
void DecayDeadBlocks() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w] > 0)
                dead_block[s][w] = 0; // Periodically reset dead-block bits
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DSD-Hybrid: Final statistics." << std::endl;
    // Dead-block histogram
    uint32_t dead_cnt = 0, live_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w]) dead_cnt++; else live_cnt++;
    std::cout << "Dead blocks: " << dead_cnt << ", Live blocks: " << live_cnt << std::endl;

    // Streaming set count
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << "/" << LLC_SETS << std::endl;

    std::cout << "PSEL (DRRIP selector): " << psel << " / " << PSEL_MAX << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    if (access_count % DECAY_HEARTBEAT == 0) {
        DecayDeadBlocks();
    }
}