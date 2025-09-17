#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block tracker: 1-bit per block, 2-bit saturating counter per block ---
uint8_t dead_block[LLC_SETS][LLC_WAYS];      // 1 if block was dead on last eviction
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];        // 2-bit counter: tracks dead evictions

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- DRRIP set-dueling: 64 leader sets, 10-bit PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // start neutral
uint8_t is_leader_srrip[LLC_SETS];
uint8_t is_leader_brrip[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(dead_block, 0, sizeof(dead_block));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
    memset(is_leader_srrip, 0, sizeof(is_leader_srrip));
    memset(is_leader_brrip, 0, sizeof(is_leader_brrip));
    // Assign leader sets (first half SRRIP, second half BRRIP)
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_srrip[i] = 1;
        is_leader_brrip[LLC_SETS - 1 - i] = 1;
    }
}

// --- DRRIP: choose insertion policy per set ---
inline uint8_t get_drrip_policy(uint32_t set) {
    if (is_leader_srrip[set]) return 0; // SRRIP
    if (is_leader_brrip[set]) return 1; // BRRIP
    return (PSEL >= (1 << (PSEL_BITS - 1))) ? 0 : 1; // majority
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
    // Streaming sets: bypass allocation (no victim)
    if (streaming_flag[set]) return LLC_WAYS; // special value: bypass

    // Standard RRIP victim selection (evict block with RRPV==3)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
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

    // --- Streaming sets: bypass allocation ---
    if (streaming_flag[set] && !hit) {
        // Do not allocate on miss
        return;
    }

    // --- Dead-block tracker update ---
    if (hit) {
        // Promote to MRU
        rrpv[set][way] = 0;
        // Block was reused: clear dead flag, decay counter
        dead_block[set][way] = 0;
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
    } else {
        // On miss/insert: choose insertion depth
        uint8_t ins_rrpv = 2; // default SRRIP
        uint8_t policy = get_drrip_policy(set);
        if (policy == 0) ins_rrpv = 2; // SRRIP: insert at RRPV=2
        else if (policy == 1) ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: mostly LRU

        // Dead-block counter: if block was dead in past, insert at LRU
        if (dead_ctr[set][way] >= 2) ins_rrpv = 3;

        rrpv[set][way] = ins_rrpv;

        // On eviction: update dead-block counter for victim block
        if (!hit) {
            uint8_t victim_way = way;
            if (rrpv[set][victim_way] == 3 && dead_block[set][victim_way] == 0) {
                // Block was not reused before eviction: mark as dead
                dead_block[set][victim_way] = 1;
                if (dead_ctr[set][victim_way] < 3) dead_ctr[set][victim_way]++;
            }
        }

        // DRRIP set-dueling: update PSEL on leader sets
        if (is_leader_srrip[set] && hit) {
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        }
        if (is_leader_brrip[set] && hit) {
            if (PSEL > 0) PSEL--;
        }
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (streaming_flag[s]) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w] >= 2) dead_blocks++;
        }
    }
    std::cout << "DRRIP-SBDT: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "DRRIP-SBDT: Dead-prone blocks: " << dead_blocks << std::endl;
    std::cout << "DRRIP-SBDT: PSEL value: " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "DRRIP-SBDT: Streaming sets: " << streaming_sets << std::endl;
}