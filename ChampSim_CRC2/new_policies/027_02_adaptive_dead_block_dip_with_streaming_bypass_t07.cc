#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP Set-dueling: leader sets and PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;
bool is_lip_leader(uint32_t set) { return set % (LLC_SETS / NUM_LEADER_SETS) == 0; }
bool is_bip_leader(uint32_t set) { return set % (LLC_SETS / NUM_LEADER_SETS) == 1; }

// --- Per-block dead-block predictor: 2 bits per block ---
uint8_t dbp_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector: 2 bits per set, last address/delta per set ---
uint8_t stream_ctr[LLC_SETS];
uint64_t last_addr[LLC_SETS];
uint64_t last_delta[LLC_SETS];

// --- RRIP bits per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Periodic decay for DBP ---
uint64_t global_access_counter = 0;
#define DBP_DECAY_INTERVAL 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dbp_ctr, 0, sizeof(dbp_ctr));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    PSEL = PSEL_MAX / 2;
    global_access_counter = 0;
}

// Find victim block in set: use RRIP, prefer blocks with dbp_ctr==3
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks (dbp_ctr==3), else standard RRIP policy
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dbp_ctr[set][way] == 3)
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
    global_access_counter++;
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

    bool streaming = (stream_ctr[set] >= 2);

    // --- Dead-block counter update: increment on miss, reset on hit ---
    if (hit) {
        dbp_ctr[set][way] = 0;
        rrpv[set][way] = 0;
    } else {
        // On miss: victim block is evicted, increment its dead-block counter
        dbp_ctr[set][way] = dbp_ctr[set][way] < 3 ? dbp_ctr[set][way] + 1 : 3;
    }

    // --- Streaming bypass logic ---
    if (streaming) {
        rrpv[set][way] = 3; // streaming: insert at distant RRPV
        dbp_ctr[set][way] = 0;
        return;
    }

    // --- DIP-style insertion depth: choose between LIP/BIP ---
    uint8_t ins_rrpv = 3; // default LIP (insert at RRPV=3)
    if (is_lip_leader(set)) {
        ins_rrpv = 3; // LIP: always insert at distant RRPV
    } else if (is_bip_leader(set)) {
        // BIP: insert at RRPV=3 31/32 times, at RRPV=0 1/32 times
        static uint32_t bip_count = 0;
        bip_count = (bip_count + 1) % 32;
        ins_rrpv = (bip_count == 0) ? 0 : 3;
    } else {
        // Follower sets: use PSEL to choose
        ins_rrpv = (PSEL >= PSEL_MAX / 2) ? 3 : 0;
    }

    // Dead-block counter override: if the block was predicted dead, insert at RRPV=3 always
    if (dbp_ctr[set][way] == 3)
        ins_rrpv = 3;

    rrpv[set][way] = ins_rrpv;
    dbp_ctr[set][way] = 0;

    // --- DIP set-dueling: update PSEL ---
    if (!streaming) {
        if (is_lip_leader(set) && hit && PSEL < PSEL_MAX)
            PSEL++;
        else if (is_bip_leader(set) && hit && PSEL > 0)
            PSEL--;
    }

    // --- Periodic DBP decay ---
    if ((global_access_counter % DBP_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dbp_ctr[s][w] > 0)
                    dbp_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Adaptive Dead-Block DIP + Streaming Bypass: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << "/" << LLC_SETS << std::endl;

    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dbp_ctr[s][w] == 3)
                dead_blocks++;
    std::cout << "Dead blocks at end: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;

    std::cout << "PSEL final value: " << PSEL << " (LIP if high, BIP if low)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and dead-block histogram
}