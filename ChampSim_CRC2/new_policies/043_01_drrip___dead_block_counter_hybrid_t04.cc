#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];    // 2 bits per block

// --- DRRIP set-dueling ---
#define LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));    // 10-bit PSEL, initialized neutral
uint8_t is_srrip_leader[LLC_SETS];       // 0: normal, 1: SRRIP leader, 2: BRRIP leader

// --- Dead-block decay ---
uint64_t access_counter = 0;
#define DECAY_INTERVAL 500000

// Helper: assign leader sets
void InitLeaderSets() {
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    for (uint32_t i = 0; i < LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1; // SRRIP leader
        is_srrip_leader[LEADER_SETS + i] = 2; // BRRIP leader
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // distant
    memset(dead_ctr, 2, sizeof(dead_ctr)); // neutral
    InitLeaderSets();
    psel = (1 << (PSEL_BITS-1));
    access_counter = 0;
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Prefer blocks with dead_ctr==0 (approximate dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 0)
            return way;

    // Classic RRIP victim selection
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
    access_counter++;
    // --- Dead-block counter update ---
    if (hit) {
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        rrpv[set][way] = 0; // protect reused block
    } else {
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
    }

    // --- DRRIP insertion policy ---
    bool is_leader = (is_srrip_leader[set] != 0);
    bool use_srrip = false;
    if (is_leader) {
        use_srrip = (is_srrip_leader[set] == 1);
    } else {
        use_srrip = (psel >= (1 << (PSEL_BITS-1)));
    }

    // On fill (miss): decide insertion depth
    if (!hit) {
        if (use_srrip) {
            rrpv[set][way] = 2; // SRRIP: insert at distant
        } else {
            // BRRIP: insert at distant with low probability (1/32), else at very distant
            if ((rand() & 31) == 0)
                rrpv[set][way] = 2;
            else
                rrpv[set][way] = 3;
        }
        // Reset dead-block counter to neutral
        dead_ctr[set][way] = 2;
    }

    // --- Set-dueling: update PSEL ---
    if (is_leader && !hit) {
        if (is_srrip_leader[set] == 1 && hit)
            psel = (psel < ((1 << PSEL_BITS) - 1)) ? psel + 1 : psel;
        else if (is_srrip_leader[set] == 2 && hit)
            psel = (psel > 0) ? psel - 1 : psel;
    }

    // --- Dead-block decay ---
    if ((access_counter % DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int live_blocks = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_ctr[set][way] >= 2) live_blocks++;
            if (dead_ctr[set][way] == 0) dead_blocks++;
        }
    }
    std::cout << "DRRIP + Dead-Block Counter Hybrid Policy" << std::endl;
    std::cout << "Live blocks: " << live_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int live_blocks = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_ctr[set][way] >= 2) live_blocks++;
            if (dead_ctr[set][way] == 0) dead_blocks++;
        }
    }
    std::cout << "Live blocks (heartbeat): " << live_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (heartbeat): " << psel << std::endl;
}