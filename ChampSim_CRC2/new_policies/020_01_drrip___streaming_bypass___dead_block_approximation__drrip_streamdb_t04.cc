#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV, set-dueling, 10-bit PSEL ---
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t PSEL = PSEL_MAX / 2;

#define NUM_LEADER_SETS 32
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: 2-bit per-set stride counter, 1-bit streaming flag ---
uint8_t stride_count[LLC_SETS];     // Counts monotonic fills (0-3)
uint64_t last_addr[LLC_SETS];       // Last filled address per set
uint8_t is_streaming[LLC_SETS];     // Flag: set is streaming

// --- Dead-block approximation: 1-bit per block ---
uint8_t dead_block[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(stride_count, 0, sizeof(stride_count));
    memset(last_addr, 0, sizeof(last_addr));
    memset(is_streaming, 0, sizeof(is_streaming));
    memset(dead_block, 0, sizeof(dead_block));
    // Assign leader sets
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        leader_set_type[i] = 2; // follower
    // Pick NUM_LEADER_SETS/2 for SRRIP, NUM_LEADER_SETS/2 for BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        leader_set_type[i] = 0; // SRRIP leader
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = 1; // BRRIP leader
}

// --- Find victim: prefer dead blocks, else SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks as victims
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_block[set][way]) {
            return way;
        }
    }
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

    // --- Dead-block approximation ---
    if (hit) {
        dead_block[set][way] = 0; // Mark as not dead
        rrpv[set][way] = 0;       // MRU on hit
        return;
    }

    // --- On eviction: mark victim as dead if not reused ---
    // This is handled at insertion for the new block

    // --- Streaming bypass logic ---
    if (is_streaming[set]) {
        // Streaming detected: bypass (do not insert, if possible)
        // Champsim interface expects block to be inserted; use RRPV=3 so it is evicted soon
        rrpv[set][way] = 3;
        dead_block[set][way] = 1;
        return;
    }

    // --- DRRIP insertion policy ---
    uint8_t ins_rrpv = 2; // SRRIP default
    if (leader_set_type[set] == 0) {
        // SRRIP leader: insert at RRPV=2
        ins_rrpv = 2;
    } else if (leader_set_type[set] == 1) {
        // BRRIP leader: insert at RRPV=3 with low probability (1/32)
        ins_rrpv = ((rand() % 32) == 0) ? 2 : 3;
    } else {
        // Follower: use PSEL to choose
        if (PSEL >= (PSEL_MAX / 2)) {
            // SRRIP
            ins_rrpv = 2;
        } else {
            // BRRIP
            ins_rrpv = ((rand() % 32) == 0) ? 2 : 3;
        }
    }

    rrpv[set][way] = ins_rrpv;
    dead_block[set][way] = 1; // Mark as dead on insertion

    // --- Update PSEL for leader sets ---
    if (leader_set_type[set] == 0) {
        // SRRIP leader: increment PSEL on hit, decrement on miss
        if (hit && PSEL < PSEL_MAX) PSEL++;
        else if (!hit && PSEL > 0) PSEL--;
    } else if (leader_set_type[set] == 1) {
        // BRRIP leader: decrement PSEL on hit, increment on miss
        if (hit && PSEL > 0) PSEL--;
        else if (!hit && PSEL < PSEL_MAX) PSEL++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP-StreamDB: Final statistics." << std::endl;
    uint32_t streaming_sets = 0, dead_blocks = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (is_streaming[i]) streaming_sets++;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        for (uint32_t j = 0; j < LLC_WAYS; ++j)
            if (dead_block[i][j]) dead_blocks++;
    std::cout << "Streaming sets detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks marked: " << dead_blocks << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and dead block count
}