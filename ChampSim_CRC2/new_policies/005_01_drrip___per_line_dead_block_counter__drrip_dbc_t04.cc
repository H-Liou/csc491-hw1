#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits/line
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];    // 2 bits/line

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 64
uint8_t is_srrip_leader[LLC_SETS];       // 1 bit/set
uint8_t is_brrip_leader[LLC_SETS];       // 1 bit/set
uint16_t psel = 512;                     // 10 bits, neutral start

// --- Periodic decay for dead-block counters ---
uint64_t access_counter = 0;
const uint64_t DECAY_PERIOD = 100000;    // Decay every 100K accesses

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    psel = 512;
    access_counter = 0;

    // Assign leader sets (first half SRRIP, second half BRRIP)
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[i + NUM_LEADER_SETS] = 1;
    }
}

// --- Victim selection: Prefer dead blocks, else SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, look for block with dead_ctr == 3 (max, predicted dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_ctr[set][way] == 3)
            return way;
    }
    // Next, standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
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

    // --- DRRIP insertion depth ---
    bool srrip_leader = is_srrip_leader[set];
    bool brrip_leader = is_brrip_leader[set];

    // DRRIP: choose insertion policy
    bool use_brrip = false;
    if (srrip_leader)
        use_brrip = false;
    else if (brrip_leader)
        use_brrip = true;
    else
        use_brrip = (psel < 512); // <512: favor BRRIP, >=512: favor SRRIP

    // --- On cache hit ---
    if (hit) {
        // Promote to MRU
        rrpv[set][way] = 0;
        // Block reused: reset dead counter
        dead_ctr[set][way] = 0;

        // Update PSEL for leader sets
        if (srrip_leader && psel < 1023) psel++;
        if (brrip_leader && psel > 0) psel--;
    } else {
        // On fill: insert with DRRIP policy
        if (use_brrip) {
            // BRRIP: insert at RRPV=2 (long re-reference interval) with probability 15/16, else MRU
            if ((rand() & 0xF) != 0)
                rrpv[set][way] = 2;
            else
                rrpv[set][way] = 0;
        } else {
            // SRRIP: insert at RRPV=2 always
            rrpv[set][way] = 2;
        }
        // Reset dead counter on fill
        dead_ctr[set][way] = 0;
    }

    // --- On eviction: update dead-block counter ---
    if (!hit && victim_addr) {
        // Find victim way (the way being replaced)
        // If block was not reused (dead_ctr < 3), increment dead counter
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
    }

    // --- Periodic decay of dead counters ---
    if ((access_counter % DECAY_PERIOD) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }
}

// --- Stats ---
void PrintStats() {
    int dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w] == 3) dead_blocks++;
            total_blocks++;
        }
    std::cout << "DRRIP-DBC: Dead blocks: " << dead_blocks << " / " << total_blocks << std::endl;
    std::cout << "DRRIP-DBC: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] == 3) dead_blocks++;
    std::cout << "DRRIP-DBC: Dead blocks: " << dead_blocks << std::endl;
    std::cout << "DRRIP-DBC: PSEL: " << psel << std::endl;
}