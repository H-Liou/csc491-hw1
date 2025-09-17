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

// Set-dueling: 64 leader sets (0..31 SRRIP, 32..63 BRRIP)
#define NUM_LEADER_SETS 64
#define SRRIP_LEADER_SETS 32
#define BRRIP_LEADER_SETS 32
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];

// 10-bit PSEL counter (adaptive SRRIP/BRRIP)
uint16_t psel;

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- Dead-block approximation: 2-bit reuse counter per line ---
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(reuse_ctr, 1, sizeof(reuse_ctr)); // Neutral reuse
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
    psel = 512; // Midpoint for 10 bits

    // Assign leader sets
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = (i * LLC_SETS) / NUM_LEADER_SETS;
        if (i < SRRIP_LEADER_SETS)
            is_srrip_leader[set] = 1;
        else
            is_brrip_leader[set] = 1;
    }
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
    // Streaming phase: bypass dead blocks (reuse_ctr==0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (streaming_flag[set] && reuse_ctr[set][way] == 0 && rrpv[set][way] == 3)
            return way;
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
    uint32_t block_addr = (uint32_t)(paddr >> 6);
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- Dead-block reuse counter update ---
    if (hit) {
        if (reuse_ctr[set][way] < 3)
            reuse_ctr[set][way]++;
        rrpv[set][way] = 0; // Promote to MRU
    } else {
        // On miss: decay victim's reuse counter
        if (reuse_ctr[set][way] > 0)
            reuse_ctr[set][way]--;
        // Assign neutral reuse to incoming line
        reuse_ctr[set][way] = 1;

        // --- DRRIP insertion policy ---
        uint8_t ins_rrpv = 2; // Default SRRIP
        // Set-dueling: choose SRRIP or BRRIP
        if (is_srrip_leader[set])
            ins_rrpv = 2; // SRRIP: insert at RRPV=2
        else if (is_brrip_leader[set])
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: mostly LRU, rare MRU
        else
            ins_rrpv = (psel >= 512) ? 2 : ((rand() % 32 == 0) ? 2 : 3);

        // Streaming & dead block: insert at LRU (RRPV=3)
        if (streaming_flag[set] && reuse_ctr[set][way] == 0)
            ins_rrpv = 3;

        rrpv[set][way] = ins_rrpv;

        // --- PSEL update (leader sets only) ---
        if (is_srrip_leader[set]) {
            if (hit && psel < 1023) psel++;
        } else if (is_brrip_leader[set]) {
            if (hit && psel > 0) psel--;
        }
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "DRRIP-SADB: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;

    int dead_blocks = 0, live_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (reuse_ctr[s][w] == 0) dead_blocks++;
            if (reuse_ctr[s][w] == 3) live_blocks++;
        }
    std::cout << "DRRIP-SADB: Dead blocks: " << dead_blocks << std::endl;
    std::cout << "DRRIP-SADB: Live blocks: " << live_blocks << std::endl;
    std::cout << "DRRIP-SADB: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "DRRIP-SADB: Streaming sets: " << streaming_sets << std::endl;
}