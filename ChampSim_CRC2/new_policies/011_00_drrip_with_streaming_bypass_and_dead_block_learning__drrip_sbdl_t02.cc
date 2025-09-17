#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits/line

// --- DRRIP set-dueling: 64 leader sets, 10-bit PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1)); // midpoint
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, else: follower

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- Dead-block counter: 2 bits per line ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// --- Periodic decay counter ---
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    // Assign leader sets: first 32 SRRIP, next 32 BRRIP, rest followers
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS / 2)
            leader_set_type[s] = 0; // SRRIP leader
        else if (s < NUM_LEADER_SETS)
            leader_set_type[s] = 1; // BRRIP leader
        else
            leader_set_type[s] = 2; // follower
    }
    psel = (1 << (PSEL_BITS - 1));
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
    // Streaming phase: bypass cache for blocks with high dead probability
    if (streaming_flag[set]) {
        // Find block with highest dead_ctr (prefer eviction)
        uint32_t victim = 0;
        uint8_t max_dead = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_ctr[set][way] >= max_dead && rrpv[set][way] == 3) {
                max_dead = dead_ctr[set][way];
                victim = way;
            }
        }
        return victim;
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
    access_counter++;

    // --- Streaming detector update (per set) ---
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- Dead-block counter update ---
    if (!hit) {
        // On miss, increment dead_ctr of victim line
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    } else {
        // On hit, reset dead_ctr
        dead_ctr[set][way] = 0;
    }

    // --- Periodic decay of dead-block counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }

    // --- DRRIP insertion policy ---
    uint8_t ins_rrpv = 2; // Default: SRRIP insertion (RRPV=2)
    bool is_leader = (leader_set_type[set] < 2);

    if (is_leader) {
        // Leader sets: SRRIP (ins_rrpv=2) or BRRIP (ins_rrpv=3, 1/32 probability)
        if (leader_set_type[set] == 0) {
            ins_rrpv = 2; // SRRIP
        } else {
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
        }
    } else {
        // Followers: use PSEL to choose SRRIP or BRRIP
        if (psel >= (1 << (PSEL_BITS - 1)))
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
    }

    // Streaming: bypass or insert at LRU if dead probability is high
    if (streaming_flag[set] && dead_ctr[set][way] >= 2)
        ins_rrpv = 3;

    // Dead-block learning: if dead_ctr is high, insert at LRU
    if (dead_ctr[set][way] == 3)
        ins_rrpv = 3;

    // --- RRIP update ---
    if (hit)
        rrpv[set][way] = 0; // Promote to MRU
    else
        rrpv[set][way] = ins_rrpv;

    // --- DRRIP set-dueling update ---
    if (is_leader) {
        // On hit: increment PSEL for SRRIP, decrement for BRRIP
        if (leader_set_type[set] == 0 && hit && psel < ((1 << PSEL_BITS) - 1))
            psel++;
        else if (leader_set_type[set] == 1 && hit && psel > 0)
            psel--;
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "DRRIP-SBDL: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;

    int dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] == 3) dead_blocks++;
    std::cout << "DRRIP-SBDL: Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;

    std::cout << "DRRIP-SBDL: PSEL value: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "DRRIP-SBDL: Streaming sets: " << streaming_sets << std::endl;
    std::cout << "DRRIP-SBDL: PSEL value: " << psel << std::endl;
}