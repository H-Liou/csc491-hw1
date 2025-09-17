#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
// 2-bit RRPV per line
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block tracking: 1-bit per line ---
uint8_t dead_bit[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- DRRIP set-dueling: 64 leader sets, 10-bit PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // initialize to midpoint

// Leader set mapping
bool is_srrip_leader(uint32_t set) { return (set % NUM_LEADER_SETS) == 0; }
bool is_brrip_leader(uint32_t set) { return (set % NUM_LEADER_SETS) == 1; }

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(dead_bit, 0, sizeof(dead_bit));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
    PSEL = (1 << (PSEL_BITS - 1));
}

// --- Victim selection: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming phase: bypass cache for blocks predicted dead
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (streaming_flag[set] && dead_bit[set][way]) {
            // Prefer to evict dead blocks during streaming
            if (rrpv[set][way] == 3)
                return way;
        }
    }
    // Normal RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
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
    // --- Streaming detector update (per set) ---
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- Dead-block tracking ---
    if (hit) {
        dead_bit[set][way] = 0; // Mark as live on hit
        rrpv[set][way] = 0;     // Promote to MRU
    } else {
        // Mark victim as dead
        dead_bit[set][way] = 1;

        // --- DRRIP insertion policy ---
        uint8_t ins_rrpv = 2; // SRRIP default
        // Set-dueling: choose insertion policy
        if (is_srrip_leader(set)) {
            ins_rrpv = 2; // SRRIP: insert at RRPV=2
            // Update PSEL if hit
            if (hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        } else if (is_brrip_leader(set)) {
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at RRPV=2 with low probability
            // Update PSEL if hit
            if (hit && PSEL > 0) PSEL--;
        } else {
            // Non-leader sets: use PSEL to choose
            if (PSEL >= (1 << (PSEL_BITS - 1))) {
                ins_rrpv = 2; // SRRIP
            } else {
                ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
            }
        }
        // Streaming phase: bypass blocks predicted dead
        if (streaming_flag[set]) {
            if (dead_bit[set][way])
                ins_rrpv = 3; // Insert at LRU if predicted dead
        }
        rrpv[set][way] = ins_rrpv;
    }

    // --- Dead-block periodic decay (every 4096 misses) ---
    static uint64_t global_miss_count = 0;
    if (!hit) {
        global_miss_count++;
        if ((global_miss_count & 0xFFF) == 0) { // every 4096 misses
            for (uint32_t s = 0; s < LLC_SETS; ++s)
                for (uint32_t w = 0; w < LLC_WAYS; ++w)
                    dead_bit[s][w] = 0; // decay: reset all to live
        }
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (streaming_flag[s]) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_bit[s][w]) dead_blocks++;
    }
    std::cout << "DRRIP-SBDT: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "DRRIP-SBDT: Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "DRRIP-SBDT: PSEL: " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "DRRIP-SBDT: Streaming sets: " << streaming_sets << std::endl;
}