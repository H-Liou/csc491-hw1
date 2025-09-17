#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Per-line PC signature (6 bits) ----
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// ---- Per-line dead-block counter (2 bits) ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- DIP-style set-dueling: 64 leader sets for LIP, 64 for BIP ----
#define NUM_LEADER_SETS 64
uint8_t is_lip_leader[LLC_SETS];
uint8_t is_bip_leader[LLC_SETS];

// ---- PSEL counter: 10 bits ----
uint16_t psel = 512; // 0..1023, LIP if psel >= 512, else BIP

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

// Helper: hash PC to 6 bits
inline uint8_t get_pc_sig(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F; // 6 bits
}

// Helper: assign leader sets for DIP
void assign_leader_sets() {
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    memset(is_bip_leader, 0, sizeof(is_bip_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS - 1 - i] = 1;
    }
}

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 3;
            pc_sig[set][way] = 0;
            dead_ctr[set][way] = 2; // start blocks as "weakly alive"
        }
    }
    assign_leader_sets();
    psel = 512;
    access_counter = 0;
}

// Find victim in the set (RRIP)
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

    uint8_t sig = get_pc_sig(PC);

    // Update dead-block counter on eviction (miss)
    if (!hit) {
        // On miss, if victim's dead_ctr==0, reinforce dead prediction
        // Otherwise, decay dead_ctr
        uint8_t victim_way = way;
        if (dead_ctr[set][victim_way] > 0)
            dead_ctr[set][victim_way]--;
    } else {
        // On hit, promote block and reinforce alive prediction
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
        rrpv[set][way] = 0;
    }

    // Update PC signature
    pc_sig[set][way] = sig;

    // DIP-style insertion policy
    bool use_lip = true;
    if (is_lip_leader[set])
        use_lip = true;
    else if (is_bip_leader[set])
        use_lip = false;
    else
        use_lip = (psel >= 512);

    // Determine insertion depth
    uint8_t insert_rrpv = 0;
    if (dead_ctr[set][way] == 0) {
        // Predicted dead: insert at LRU (bypass)
        insert_rrpv = 3;
    } else {
        // Alive or uncertain: insertion policy
        if (use_lip)
            insert_rrpv = 3; // LIP: always insert at LRU
        else {
            // BIP: insert at MRU with 1/32 probability, else LRU
            if ((access_counter & 0x1F) == 0)
                insert_rrpv = 0;
            else
                insert_rrpv = 3;
        }
    }
    rrpv[set][way] = insert_rrpv;

    // DIP: update PSEL for leader sets
    if (is_lip_leader[set]) {
        if (hit && insert_rrpv == 3) // reward LIP leader for hit on LRU insertion
            if (psel < 1023) psel++;
    } else if (is_bip_leader[set]) {
        if (hit && insert_rrpv == 0) // reward BIP leader for hit on MRU insertion
            if (psel > 0) psel--;
    }

    // Periodic decay of dead-block counters
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t set_ = 0; set_ < LLC_SETS; ++set_)
            for (uint32_t way_ = 0; way_ < LLC_WAYS; ++way_)
                if (dead_ctr[set_][way_] > 0)
                    dead_ctr[set_][way_]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks = 0, alive_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 0) dead_blocks++;
            else if (dead_ctr[set][way] >= 2) alive_blocks++;
    std::cout << "PC-LIP Policy: PC-Signature Guided LRU Insertion + Dead-Block Bypass" << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "Alive blocks: " << alive_blocks << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0, alive_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 0) dead_blocks++;
            else if (dead_ctr[set][way] >= 2) alive_blocks++;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "Alive blocks (heartbeat): " << alive_blocks << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "PSEL value (heartbeat): " << psel << std::endl;
}