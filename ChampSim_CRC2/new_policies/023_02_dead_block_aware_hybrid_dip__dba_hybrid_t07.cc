#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Dead-block detector: 1 bit per line ---
uint8_t dead_bit[LLC_SETS][LLC_WAYS]; // 1 bit per block

// --- DIP set-dueling: LIP vs BIP ---
#define NUM_LEADER_SETS 32
uint8_t is_lip_leader[LLC_SETS];
uint8_t is_bip_leader[LLC_SETS];
uint16_t psel; // 10 bits

// --- Periodic decay for dead bits ---
uint64_t access_counter = 0; // for periodic decay

void InitReplacementState() {
    // Initialize RRIP to max (3)
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            rrpv[s][w] = 3;
    // Initialize dead bits to 0
    memset(dead_bit, 0, sizeof(dead_bit));
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    memset(is_bip_leader, 0, sizeof(is_bip_leader));
    psel = (1 << 9); // 512
    // Assign leader sets: first NUM_LEADER_SETS for LIP, next NUM_LEADER_SETS for BIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS/2 + i] = 1;
    }
    access_counter = 0;
}

// --- Find victim in the set ---
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
    // Prefer dead blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_bit[set][way] == 1)
            return way;
    // RRIP: select block with max RRPV (3), else increment all RRPV
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
    access_counter++;
    // --- Dead-block update ---
    if (hit) {
        // Block reused: mark as live
        dead_bit[set][way] = 0;
        rrpv[set][way] = 0; // promote to MRU
    } else {
        // Block not reused on eviction: mark as dead
        dead_bit[set][way] = 1;
        // leave RRPV unchanged (will be set on fill)
    }

    // --- Determine insertion policy via set-dueling DIP ---
    bool use_lip = false;
    if (is_lip_leader[set])
        use_lip = true;
    else if (is_bip_leader[set])
        use_lip = false;
    else
        use_lip = (psel < (1 << 9));

    // --- Dead-block aware insertion ---
    uint8_t insertion_rrpv = 2; // default distant
    // If previous block (victim) was dead, insert at max RRPV (3) or bypass
    if (dead_bit[set][way] == 1) {
        insertion_rrpv = 3; // insert at farthest position
        // Optionally, bypass: with 10% probability for dead blocks in streaming sets
        if ((rand() % 10) == 0)
            return; // bypass: don't insert (simulate by not updating RRPV/dead_bit)
    }
    else {
        if (use_lip) {
            insertion_rrpv = 3; // LIP: always insert at farthest
        } else {
            insertion_rrpv = ((rand() % 32) == 0) ? 0 : 3; // BIP: 1/32 at MRU, rest at farthest
        }
    }
    rrpv[set][way] = insertion_rrpv;
    dead_bit[set][way] = 0; // new block assumed live

    // --- DIP set-dueling PSEL update ---
    if (is_lip_leader[set]) {
        if (hit && psel < 1023) psel++;
    } else if (is_bip_leader[set]) {
        if (hit && psel > 0) psel--;
    }

    // --- Periodic decay of dead bits every 4096 fills ---
    if ((access_counter & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_bit[s][w] == 1)
                    dead_bit[s][w] = 0; // decay: reset to live
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int dead_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_bit[s][w] == 1)
                dead_lines++;
    std::cout << "DBA-Hybrid Policy: Dead-block Aware Hybrid DIP" << std::endl;
    std::cout << "Total dead lines: " << dead_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int dead_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_bit[s][w] == 1)
                dead_lines++;
    std::cout << "Dead lines (heartbeat): " << dead_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (heartbeat): " << psel << std::endl;
}