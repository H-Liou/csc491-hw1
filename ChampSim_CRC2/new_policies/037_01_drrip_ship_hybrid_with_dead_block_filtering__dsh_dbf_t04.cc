#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: 6-bit signature per block, 2-bit outcome table ----
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 2048 // 2K entries
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block
uint8_t ship_table[SHIP_SIG_ENTRIES];  // 2 bits per entry

// ---- Dead-block filter: 2 bits per block ----
uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- DRRIP set-dueling ----
#define PSEL_BITS 10
uint16_t PSEL = 512; // 10 bits, midpoint
#define NUM_LEADER_SETS 64
std::vector<uint32_t> srrip_leader_sets;
std::vector<uint32_t> brrip_leader_sets;

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DBF_DECAY_PERIOD 4096

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;        // Default distant insertion
            block_sig[set][way] = 0;
            dead_block[set][way] = 0;
        }
    }
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        ship_table[i] = 1; // Neutral reuse

    // Assign leader sets for DRRIP set-dueling
    srrip_leader_sets.clear();
    brrip_leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        srrip_leader_sets.push_back(i);
        brrip_leader_sets.push_back(LLC_SETS - 1 - i);
    }
    PSEL = 512;
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

    // --- Dead-block filter decay ---
    if ((access_counter % DBF_DECAY_PERIOD) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_block[s][w] > 0)
                    dead_block[s][w]--;
    }

    // --- SHiP-lite signature calculation ---
    uint16_t sig = (PC ^ (paddr >> 6)) & SHIP_SIG_MASK;

    // --- Dead-block filter update ---
    if (hit) {
        dead_block[set][way] = 0; // Reset on reuse
    } else {
        if (dead_block[set][way] < 3)
            dead_block[set][way]++;
    }

    // --- SHiP-lite update ---
    if (hit) {
        // Block reused: increment outcome counter (max 3)
        if (ship_table[block_sig[set][way]] < 3)
            ship_table[block_sig[set][way]]++;
        rrpv[set][way] = 0; // Promote to MRU
    } else {
        // Block not reused: decrement outcome counter (min 0)
        if (ship_table[sig] > 0)
            ship_table[sig]--;
    }

    // --- DRRIP set-dueling: update PSEL on leader sets ---
    bool is_srrip_leader = std::find(srrip_leader_sets.begin(), srrip_leader_sets.end(), set) != srrip_leader_sets.end();
    bool is_brrip_leader = std::find(brrip_leader_sets.begin(), brrip_leader_sets.end(), set) != brrip_leader_sets.end();
    if (is_srrip_leader && !hit && PSEL < ((1 << PSEL_BITS) - 1))
        PSEL++;
    if (is_brrip_leader && hit && PSEL > 0)
        PSEL--;

    // --- Insertion policy ---
    block_sig[set][way] = sig;
    uint8_t insert_rrpv = 2; // default distant

    // Dead-block filtering: if dead probability high, bypass or insert at LRU
    if (dead_block[set][way] >= 2) {
        insert_rrpv = 3; // LRU insertion (simulate bypass)
    } else {
        // SHiP bias
        if (ship_table[sig] >= 2)
            insert_rrpv = 0; // MRU
        else {
            // DRRIP insertion depth
            if (is_srrip_leader)
                insert_rrpv = 2; // SRRIP: distant
            else if (is_brrip_leader)
                insert_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: mostly LRU
            else
                insert_rrpv = (PSEL >= (1 << (PSEL_BITS - 1))) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
        }
    }
    rrpv[set][way] = insert_rrpv;
}

// Print end-of-simulation statistics
void PrintStats() {
    int reused_blocks = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) reused_blocks++;
            if (dead_block[set][way] >= 2) dead_blocks++;
        }
    std::cout << "DRRIP-SHiP Hybrid + Dead-Block Filter Policy" << std::endl;
    std::cout << "MRU blocks: " << reused_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_block[set][way] >= 2) dead_blocks++;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}