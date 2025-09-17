#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV, 10-bit PSEL, set-dueling ---
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t PSEL = PSEL_MAX / 2; // Dynamic policy selector

// Leader sets: first 32 for SRRIP, next 32 for BRRIP
#define NUM_LEADER_SETS 64
#define SRRIP_LEADER_SETS 32
#define BRRIP_LEADER_SETS 32

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: 2-bit per-set stride counter, 1-bit streaming flag ---
uint8_t stride_count[LLC_SETS];     // Counts monotonic fills (0-3)
uint64_t last_addr[LLC_SETS];       // Last filled address per set
uint8_t is_streaming[LLC_SETS];     // Flag: set is streaming

// --- Dead-block approximation: 1-bit per block, periodic decay ---
uint8_t dead_block[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant
    memset(stride_count, 0, sizeof(stride_count));
    memset(last_addr, 0, sizeof(last_addr));
    memset(is_streaming, 0, sizeof(is_streaming));
    memset(dead_block, 0, sizeof(dead_block));
    PSEL = PSEL_MAX / 2;
}

// --- Helper: Is leader set? ---
inline bool is_leader_set(uint32_t set, bool &is_srrip, bool &is_brrip) {
    is_srrip = (set < SRRIP_LEADER_SETS);
    is_brrip = (set >= SRRIP_LEADER_SETS && set < NUM_LEADER_SETS);
    return is_srrip || is_brrip;
}

// --- Find victim: dead-block preferred, then SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks first
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_block[set][way])
            return way;

    // Standard SRRIP victim selection
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
    // --- Streaming detector logic ---
    if (!hit) {
        if (last_addr[set] == 0) {
            last_addr[set] = paddr;
            stride_count[set] = 0;
        } else {
            if (paddr > last_addr[set]) {
                if (stride_count[set] < 3) stride_count[set]++;
            } else {
                if (stride_count[set] > 0) stride_count[set]--;
            }
            last_addr[set] = paddr;
        }
        // Streaming if stride_count saturates
        is_streaming[set] = (stride_count[set] >= 3) ? 1 : 0;
    }

    // --- Dead-block approximation: on eviction, mark as dead ---
    if (!hit) {
        dead_block[set][way] = 1;
    } else {
        dead_block[set][way] = 0; // reused, not dead
    }

    // --- DRRIP insertion policy ---
    bool is_srrip = false, is_brrip = false;
    bool leader = is_leader_set(set, is_srrip, is_brrip);

    uint8_t ins_rrpv = 3; // default distant

    if (is_streaming[set]) {
        // Streaming detected: bypass (insert at distant RRPV, will be evicted soon)
        ins_rrpv = 3;
    } else {
        // DRRIP: choose insertion depth
        if (leader) {
            // Leader sets: always SRRIP or BRRIP
            if (is_srrip) ins_rrpv = 2; // SRRIP: insert at 2
            else ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at 2 with 1/32 probability
        } else {
            // Follower sets: use PSEL
            if (PSEL >= (PSEL_MAX / 2))
                ins_rrpv = 2; // SRRIP
            else
                ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
        }
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;

    // --- On hit: set RRPV=0, clear dead-block ---
    if (hit) {
        rrpv[set][way] = 0;
        dead_block[set][way] = 0;
    }

    // --- Update PSEL on leader sets ---
    if (leader && !hit) {
        // On miss, increment/decrement PSEL
        if (is_srrip) {
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (is_brrip) {
            if (PSEL > 0) PSEL--;
        }
    }

    // --- Dead-block periodic decay: every 4096 fills, clear all dead-block flags ---
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_block[s][w] = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP-StreamDB: Final statistics." << std::endl;
    std::cout << "PSEL value: " << PSEL << " (SRRIP if high, BRRIP if low)" << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (is_streaming[i]) streaming_sets++;
    std::cout << "Streaming sets detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w]) dead_blocks++;
    std::cout << "Dead blocks marked: " << dead_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and dead-block histogram
}