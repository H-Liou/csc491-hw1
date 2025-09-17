#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // 10-bit PSEL, initialized to midpoint
uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP

// --- Dead-block approximation: 2 bits per line ---
uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Leader set selection ---
inline bool is_leader_set(uint32_t set, uint8_t &type) {
    if (set < NUM_LEADER_SETS) {
        type = leader_set_type[set];
        return true;
    }
    return false;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_block, 0, sizeof(dead_block));
    // Assign half leader sets to SRRIP, half to BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1;
    PSEL = (1 << (PSEL_BITS - 1));
}

// --- Find victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Dead-block aware victim selection: prefer blocks with high dead-block counter
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 && dead_block[set][way] == 3)
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
    uint8_t leader_type;
    bool is_leader = is_leader_set(set, leader_type);

    // --- Dead-block counter update ---
    if (hit) {
        // On hit, reset dead-block counter and promote block
        dead_block[set][way] = 0;
        rrpv[set][way] = 0;
        // Update PSEL for leader sets
        if (is_leader) {
            if (leader_type == 0 && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++; // SRRIP leader: increment
            if (leader_type == 1 && PSEL > 0) PSEL--; // BRRIP leader: decrement
        }
        return;
    } else {
        // On miss, increment dead-block counter (max 3)
        if (dead_block[set][way] < 3) dead_block[set][way]++;
    }

    // --- DRRIP insertion depth selection ---
    uint8_t ins_rrpv;
    if (is_leader) {
        ins_rrpv = (leader_type == 0) ? 2 : ((rand() & 0x1F) == 0 ? 2 : 3); // SRRIP: 2, BRRIP: mostly 3
    } else {
        ins_rrpv = (PSEL >= (1 << (PSEL_BITS - 1))) ? 2 : ((rand() & 0x1F) == 0 ? 2 : 3);
    }

    // --- Dead-block aware insertion/bypass ---
    if (dead_block[set][way] == 3) {
        // If block is likely dead, insert at distant RRPV or bypass (no allocation)
        if ((rand() & 0x7) == 0) {
            // Bypass: mark block as invalid (simulate not allocating)
            rrpv[set][way] = 3;
            return;
        } else {
            rrpv[set][way] = 3;
            return;
        }
    }

    // Normal insertion
    rrpv[set][way] = ins_rrpv;
}

// --- Periodic decay of dead-block counters ---
void DecayDeadBlockCounters() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w] > 0) dead_block[s][w]--;
}

// --- Stats ---
void PrintStats() {
    int dead_lines = 0, total = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_block[s][w] == 3) dead_lines++;
            total++;
        }
    std::cout << "DRRIP-DBA Policy: DRRIP + Dead-Block Approximation" << std::endl;
    std::cout << "Dead-block lines detected: " << dead_lines << "/" << total << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    // Decay dead-block counters every heartbeat
    DecayDeadBlockCounters();
    int dead_lines = 0, total = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w] == 3) dead_lines++;
    std::cout << "[Heartbeat] Dead-block lines: " << dead_lines << std::endl;
}