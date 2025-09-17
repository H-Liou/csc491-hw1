#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
// 2 bits/line RRPV
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 1 bit/line dead-block flag
uint8_t dead_flag[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set 1-bit flag, last block address
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// DRRIP set-dueling: 32 leader sets/policy
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t PSEL; // 10-bit selector

std::vector<uint32_t> srrip_leader_sets;
std::vector<uint32_t> brrip_leader_sets;

// Helper: initialize leader sets
void InitLeaderSets() {
    srrip_leader_sets.clear();
    brrip_leader_sets.clear();
    for (uint32_t i = 0; i < LLC_SETS && (srrip_leader_sets.size() < NUM_LEADER_SETS || brrip_leader_sets.size() < NUM_LEADER_SETS); ++i) {
        if (srrip_leader_sets.size() < NUM_LEADER_SETS && (i % 64 == 0)) // every 64th set
            srrip_leader_sets.push_back(i);
        else if (brrip_leader_sets.size() < NUM_LEADER_SETS && (i % 64 == 32)) // offset for brrip
            brrip_leader_sets.push_back(i);
    }
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(dead_flag, 0, sizeof(dead_flag));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
    PSEL = (1 << (PSEL_BITS - 1)); // Neutral value
    InitLeaderSets();
}

// --- Victim selection: RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // If streaming detected, bypass cache for dead blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (streaming_flag[set] && dead_flag[set][way]) {
            // Prefer to evict dead blocks during streaming
            if (rrpv[set][way] == 3)
                return way;
        }
    }
    // Standard RRIP victim selection
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

// --- Replacement state update ---
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
    uint32_t block_addr = (uint32_t)(paddr >> 6);
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- Dead-block predictor update ---
    // If hit: clear dead flag
    if (hit) {
        dead_flag[set][way] = 0;
        rrpv[set][way] = 0; // Promote to MRU
    } else {
        // On miss: set dead-flag for victim way if not reused since last fill
        if (!dead_flag[set][way])
            dead_flag[set][way] = 1;
        // Periodic decay: clear all dead flags every 8192 fills
        static uint64_t fill_count = 0;
        fill_count++;
        if (fill_count % 8192 == 0) {
            for (uint32_t s = 0; s < LLC_SETS; ++s)
                for (uint32_t w = 0; w < LLC_WAYS; ++w)
                    dead_flag[s][w] = 0;
        }
    }

    // --- DRRIP insertion policy ---
    bool is_srrip_leader = (std::find(srrip_leader_sets.begin(), srrip_leader_sets.end(), set) != srrip_leader_sets.end());
    bool is_brrip_leader = (std::find(brrip_leader_sets.begin(), brrip_leader_sets.end(), set) != brrip_leader_sets.end());
    bool use_brrip = false;

    if (is_srrip_leader)
        use_brrip = false;
    else if (is_brrip_leader)
        use_brrip = true;
    else
        use_brrip = (PSEL < (1 << (PSEL_BITS - 1))); // PSEL < midpoint => BRRIP

    // BRRIP: insert at RRPV=2 most of the time, RRPV=3 occasionally (1/32)
    uint8_t ins_rrpv = 2;
    if (use_brrip) {
        static uint32_t randval = 0;
        randval = (randval * 1103515245 + 12345) & 0x7fffffff;
        if ((randval & 0x1f) == 0) // 1/32
            ins_rrpv = 3;
        else
            ins_rrpv = 2;
    } else {
        ins_rrpv = 2; // SRRIP: always insert at RRPV=2
    }

    // If streaming detected and dead block, insert at LRU (RRPV=3)
    if (streaming_flag[set] && dead_flag[set][way])
        ins_rrpv = 3;

    // Insert new block
    rrpv[set][way] = ins_rrpv;
    dead_flag[set][way] = 0; // New block: not dead

    // --- Set-dueling update ---
    if (is_srrip_leader && !hit) {
        if (PSEL < ((1 << PSEL_BITS) - 1))
            PSEL++;
    } else if (is_brrip_leader && !hit) {
        if (PSEL > 0)
            PSEL--;
    }
}

// --- Statistics ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "DRRIP-SADB: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;

    int dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_flag[s][w]) dead_blocks++;
    std::cout << "DRRIP-SADB: Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;

    std::cout << "DRRIP-SADB: PSEL value: " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "DRRIP-SADB: Streaming sets: " << streaming_sets << std::endl;
}