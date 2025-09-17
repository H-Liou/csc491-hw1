#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits per block

// --- Dead-block approximation ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];  // 2 bits per block

// --- DRRIP set-dueling: 64 leader sets (SRRIP/BRRIP) ---
#define NUM_LEADER_SETS 64
uint8_t is_sr_leader[LLC_SETS];        // 1 if SRRIP leader, 2 if BRRIP leader, 0 otherwise

// --- DRRIP PSEL counter: 10 bits ---
uint16_t psel = 512;                   // Range [0,1023]

// --- Dead-block periodic decay ---
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    // Leader set selection: every LLC_SETS/(2*NUM_LEADER_SETS)th set is a leader
    memset(is_sr_leader, 0, sizeof(is_sr_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t sr_set = (i * LLC_SETS) / (2 * NUM_LEADER_SETS);
        uint32_t br_set = ((i + NUM_LEADER_SETS) * LLC_SETS) / (2 * NUM_LEADER_SETS);
        is_sr_leader[sr_set] = 1;
        is_sr_leader[br_set] = 2;
    }
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;   // SRRIP default
            dead_ctr[set][way] = 1; // weakly alive
        }
    psel = 512;
    access_counter = 0;
}

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

    // Dead-block victim: if any block's dead_ctr == 0, evict immediately
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 0)
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

    // On hit: increase dead-block counter, promote to MRU
    if (hit) {
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
        rrpv[set][way] = 0; // MRU
    } else {
        // On miss: decrease dead-block counter (if not zero)
        if (dead_ctr[set][way] > 0)
            dead_ctr[set][way]--;
    }

    // --- DRRIP insertion policy ---
    bool is_leader = (is_sr_leader[set] != 0);
    bool use_srrip = false;
    if (is_leader) {
        use_srrip = (is_sr_leader[set] == 1);
    } else {
        use_srrip = (psel >= 512);
    }
    // On install: choose insertion depth
    if (!hit) {
        if (use_srrip) {
            rrpv[set][way] = 2; // SRRIP: insert at RRPV=2
        } else {
            rrpv[set][way] = (rand() & 0xF) == 0 ? 2 : 3; // BRRIP: insert at 3 most of time, 2 rarely
        }
    }

    // --- DRRIP set-dueling update ---
    if (is_leader) {
        if (hit) {
            if (is_sr_leader[set] == 1 && psel < 1023)
                psel++;
            else if (is_sr_leader[set] == 2 && psel > 0)
                psel--;
        }
        // No update on miss for PSEL
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
            if (dead_ctr[set][way] == 0)
                dead_blocks++;
    std::cout << "DRRIP-DeadBlock Hybrid Policy" << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value: " << psel << " (SRRIP if >=512, BRRIP if <512)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 0)
                dead_blocks++;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (heartbeat): " << psel << std::endl;
}