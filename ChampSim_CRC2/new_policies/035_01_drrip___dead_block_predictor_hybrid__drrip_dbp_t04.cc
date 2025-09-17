#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Dead-block predictor: 2 bits per block ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- DRRIP set-dueling ----
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t psel = PSEL_MAX / 2; // 10-bit PSEL counter

// Leader sets: 64 total (32 SRRIP, 32 BRRIP)
#define NUM_LEADER_SETS 64
#define SRRIP_LEADER_SETS 32
#define BRRIP_LEADER_SETS 32
uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP

// Map LLC set to leader set (if any), else 0xFF
uint8_t set_leader_map[LLC_SETS];

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    // Initialize RRIP and dead-block counters
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // SRRIP default insertion
            dead_ctr[set][way] = 0;
        }
    }
    // Assign leader sets: evenly distributed
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_set_type[i] = (i < SRRIP_LEADER_SETS) ? 0 : 1;
    }
    // Map sets to leader sets (spread evenly)
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set % (LLC_SETS / NUM_LEADER_SETS) == 0)
            set_leader_map[set] = set / (LLC_SETS / NUM_LEADER_SETS);
        else
            set_leader_map[set] = 0xFF;
    }
    psel = PSEL_MAX / 2;
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

    // --- Dead-block predictor update ---
    if (hit) {
        // On hit, block is reused: reset deadness
        dead_ctr[set][way] = 0;
        rrpv[set][way] = 0; // promote to MRU
    } else {
        // On miss, increment deadness (max 3)
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // --- DRRIP set-dueling ---
    uint8_t leader_idx = set_leader_map[set];
    bool is_leader = (leader_idx != 0xFF);
    bool use_brrip = false;
    if (is_leader) {
        use_brrip = (leader_set_type[leader_idx] == 1);
    } else {
        use_brrip = (psel >= (PSEL_MAX / 2));
    }

    // --- Insertion policy ---
    if (dead_ctr[set][way] == 3) {
        // Block predicted dead: insert at LRU (RRPV=3)
        rrpv[set][way] = 3;
    } else {
        // DRRIP insertion
        if (use_brrip) {
            // BRRIP: insert at RRPV=2 (long re-reference interval) most times, RRPV=0 rarely
            if ((access_counter & 0x1F) == 0) // 1/32 probability
                rrpv[set][way] = 0;
            else
                rrpv[set][way] = 2;
        } else {
            // SRRIP: insert at RRPV=2
            rrpv[set][way] = 2;
        }
    }

    // --- PSEL adjustment for leader sets ---
    if (is_leader && !hit) {
        // On miss in leader set, adjust PSEL
        if (leader_set_type[leader_idx] == 0) {
            // SRRIP leader: increment PSEL
            if (psel < PSEL_MAX) psel++;
        } else {
            // BRRIP leader: decrement PSEL
            if (psel > 0) psel--;
        }
    }

    // --- Periodic decay of dead-block counters ---
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
    std::cout << "DRRIP-DBP Policy: DRRIP + Dead-Block Predictor Hybrid" << std::endl;
    std::cout << "Dead blocks (counter=3): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value: " << psel << " (max " << PSEL_MAX << ")" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead_blocks++;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (heartbeat): " << psel << std::endl;
}