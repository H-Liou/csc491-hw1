#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];  // 2 bits per block

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 64
uint8_t is_srrip_leader[LLC_SETS];     // 0: normal, 1: SRRIP leader, 2: BRRIP leader
uint16_t psel = 512;                   // 10-bit PSEL counter (0-1023)

// Helper: select leader sets (first 32 SRRIP, next 32 BRRIP)
void InitLeaderSets() {
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        is_srrip_leader[i] = 1; // SRRIP leader
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        is_srrip_leader[i] = 2; // BRRIP leader
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;      // distant
            dead_ctr[set][way] = 1;  // neutral
        }
    InitLeaderSets();
    psel = 512;
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
    // Prefer block with dead_ctr == 3 (dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
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
    // --- Dead-block counter update ---
    if (hit) {
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
        rrpv[set][way] = 0; // protect reused block
    } else {
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
    }

    // --- DRRIP insertion policy ---
    bool use_srrip = false;
    if (is_srrip_leader[set] == 1)
        use_srrip = true;
    else if (is_srrip_leader[set] == 2)
        use_srrip = false;
    else
        use_srrip = (psel >= 512);

    // On miss (new insertion)
    if (!hit) {
        // SRRIP: insert at RRPV=2 (distant)
        // BRRIP: insert at RRPV=3 (very distant) with low probability (1/32), else at 2
        if (use_srrip) {
            rrpv[set][way] = 2;
        } else {
            if ((rand() & 31) == 0)
                rrpv[set][way] = 3;
            else
                rrpv[set][way] = 2;
        }
        dead_ctr[set][way] = 1; // reset dead counter on fill
    }

    // --- Set-dueling: update PSEL on leader sets ---
    if (is_srrip_leader[set] == 1) {
        // SRRIP leader: increment PSEL on hit, decrement on miss
        if (hit && psel < 1023) psel++;
        else if (!hit && psel > 0) psel--;
    } else if (is_srrip_leader[set] == 2) {
        // BRRIP leader: decrement PSEL on hit, increment on miss
        if (hit && psel > 0) psel--;
        else if (!hit && psel < 1023) psel++;
    }

    // --- Periodic decay of dead counters ---
    static uint64_t access_count = 0;
    access_count++;
    if (access_count % (LLC_SETS * LLC_WAYS) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int live_blocks = 0, dead_blocks = 0, srrip_leader_hits = 0, brrip_leader_hits = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_ctr[set][way] == 0) live_blocks++;
            if (dead_ctr[set][way] == 3) dead_blocks++;
        }
    }
    std::cout << "DRRIP + Dead-Block Counter Hybrid Policy" << std::endl;
    std::cout << "Live blocks: " << live_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int live_blocks = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_ctr[set][way] == 0) live_blocks++;
            if (dead_ctr[set][way] == 3) dead_blocks++;
        }
    std::cout << "Live blocks (heartbeat): " << live_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}