#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// -- RRIP Metadata --
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// -- Set-dueling: SRRIP vs BRRIP --
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel;
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower

// -- Dead-block predictor: SHiP signature + outcome --
#define SIG_BITS 6
#define CTR_BITS 2
uint8_t dbi_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block
uint8_t dbi_ctr[LLC_SETS][LLC_WAYS];       // 2 bits per block

// -- Periodic decay --
uint64_t access_counter = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dbi_signature, 0, sizeof(dbi_signature));
    memset(dbi_ctr, 1, sizeof(dbi_ctr)); // Start at weak reuse
    psel = (1 << (PSEL_BITS - 1));
    // Assign leader sets: evenly distributed
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS / 2) leader_set_type[s] = 0; // SRRIP
        else if (s < NUM_LEADER_SETS) leader_set_type[s] = 1; // BRRIP
        else leader_set_type[s] = 2; // follower
    }
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>(PC ^ (PC >> 6)) & ((1 << SIG_BITS) - 1);
}

// --- Dead-block predictor decay (periodic) ---
inline void dbi_decay() {
    if ((access_counter & 0xFFF) == 0) { // every 4096 LLC accesses
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (dbi_ctr[set][way] > 0)
                    dbi_ctr[set][way]--;
    }
}

// --- Victim selection ---
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
    access_counter++;
    if ((access_counter & 0xFFF) == 0) dbi_decay();

    uint8_t sig = get_signature(PC);

    // On hit: promote block, increment reuse counter
    if (hit) {
        rrpv[set][way] = 0;
        if (dbi_ctr[set][way] < 3) dbi_ctr[set][way]++;
        return;
    }

    // --- Set-dueling: choose base insertion RRIP ---
    uint8_t base_rrpv = 2; // SRRIP default: insert at RRPV 2
    if (leader_set_type[set] == 0) { // SRRIP leader
        base_rrpv = 2;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        base_rrpv = (rand() % 32 == 0) ? 2 : 3; // Insert at RRPV 2 with 1/32 probability, else RRPV 3 (distant)
    } else { // follower
        base_rrpv = (psel >= (1 << (PSEL_BITS - 1))) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
    }

    // --- Dead-block insertion override ---
    // If reuse counter is low (dbi_ctr==0), insert at RRPV 3 (distant, early eviction)
    // If reuse counter is high (dbi_ctr==3), insert at RRPV 0 (MRU, long retention)
    uint8_t insertion_rrpv = base_rrpv;
    if (dbi_ctr[set][way] == 0)
        insertion_rrpv = 3;
    else if (dbi_ctr[set][way] == 3)
        insertion_rrpv = 0;

    rrpv[set][way] = insertion_rrpv;
    dbi_signature[set][way] = sig;
    dbi_ctr[set][way] = 1; // weak reuse by default

    // --- PSEL update for set-dueling ---
    if (leader_set_type[set] == 0) { // SRRIP leader
        if (hit) { if (psel < ((1 << PSEL_BITS) - 1)) psel++; }
        else { if (psel > 0) psel--; }
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        if (hit) { if (psel > 0) psel--; }
        else { if (psel < ((1 << PSEL_BITS) - 1)) psel++; }
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_reuse = 0, dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dbi_ctr[s][w] == 3) strong_reuse++;
            if (dbi_ctr[s][w] == 0) dead_blocks++;
            total_blocks++;
        }
    std::cout << "SRRIP-DBI Policy: Set-dueling RRIP + Dead-Block Insertion" << std::endl;
    std::cout << "Strong reuse blocks (ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Predicted dead blocks (ctr==0): " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dbi_ctr[s][w] == 3) strong_reuse++;
            if (dbi_ctr[s][w] == 0) dead_blocks++;
            total_blocks++;
        }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Predicted dead blocks (heartbeat): " << dead_blocks << "/" << total_blocks << std::endl;
}