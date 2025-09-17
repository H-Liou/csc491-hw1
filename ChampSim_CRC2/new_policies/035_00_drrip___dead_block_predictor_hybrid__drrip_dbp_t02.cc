#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Dead Block Predictor: 2 bits per block ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- DRRIP Set-Dueling ----
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 1 << (PSEL_BITS - 1); // 10-bit saturating counter

// Leader set assignment
bool is_srrip_leader[LLC_SETS];
bool is_brrip_leader[LLC_SETS];

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    // Assign leader sets
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        is_srrip_leader[set] = false;
        is_brrip_leader[set] = false;
    }
    // Evenly distribute leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = true;
        is_brrip_leader[LLC_SETS - 1 - i] = true;
    }
    // Initialize RRIP and dead block counters
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // SRRIP default insertion
            dead_ctr[set][way] = 0;
        }
    }
    PSEL = 1 << (PSEL_BITS - 1);
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

    // Prefer blocks predicted dead (dead_ctr==3)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;

    // RRIP: select block with max RRPV (3)
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

    // Dead block predictor update
    if (hit) {
        // On hit, block is reused: decrease dead counter
        if (dead_ctr[set][way] > 0)
            dead_ctr[set][way]--;
        rrpv[set][way] = 0; // promote to MRU
    } else {
        // On miss, block is not reused: increase dead counter
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // DRRIP insertion policy
    bool use_brrip = false;
    if (is_srrip_leader[set])
        use_brrip = false;
    else if (is_brrip_leader[set])
        use_brrip = true;
    else
        use_brrip = (PSEL < (1 << (PSEL_BITS - 1)));

    // If block is predicted dead, always insert at distant RRPV
    if (dead_ctr[set][way] == 3) {
        rrpv[set][way] = 3;
    } else {
        // DRRIP: SRRIP (insert at 2) or BRRIP (insert at 3 with 1/32 probability)
        if (use_brrip) {
            // BRRIP: insert at 3 with high probability, else at 2
            if ((access_counter & 0x1F) == 0)
                rrpv[set][way] = 2;
            else
                rrpv[set][way] = 3;
        } else {
            rrpv[set][way] = 2;
        }
    }

    // Update PSEL for leader sets
    if (is_srrip_leader[set]) {
        if (hit && PSEL < ((1 << PSEL_BITS) - 1))
            PSEL++;
        else if (!hit && PSEL > 0)
            PSEL--;
    } else if (is_brrip_leader[set]) {
        if (hit && PSEL > 0)
            PSEL--;
        else if (!hit && PSEL < ((1 << PSEL_BITS) - 1))
            PSEL++;
    }

    // Periodic decay of dead block counters
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (dead_ctr[set][way] > 0)
                    dead_ctr[set][way]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead_blocks++;
    std::cout << "DRRIP-DBP Policy: DRRIP + Dead Block Predictor Hybrid" << std::endl;
    std::cout << "Dead blocks (ctr==3): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead_blocks++;
    std::cout << "Dead blocks (ctr==3, heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value (heartbeat): " << PSEL << std::endl;
}