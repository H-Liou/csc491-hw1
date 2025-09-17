#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
// 6-bit PC signature per block
uint8_t block_signature[LLC_SETS][LLC_WAYS];
// 2-bit dead-block counter per block
uint8_t dead_counter[LLC_SETS][LLC_WAYS];

// SHiP outcome table: 64K entries, 2-bit counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_TABLE_SIZE];

// 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(block_signature, 0, sizeof(block_signature));
    memset(dead_counter, 0, sizeof(dead_counter));
    memset(ship_table, 1, sizeof(ship_table)); // neutral initial reuse
}

// --- Helper: get SHiP table index ---
inline uint32_t GetSHIPIndex(uint64_t PC) {
    // Use CRC to compress PC to 6 bits
    return champsim_crc2(PC, 0) & (SHIP_TABLE_SIZE - 1);
}

// --- Victim selection ---
// Prefer blocks predicted dead; else SRRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, look for block with dead_counter == 3 (dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_counter[set][way] == 3)
            return way;
    }
    // Next, standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
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
    // --- SHiP signature ---
    uint32_t sig = GetSHIPIndex(PC);

    if (hit) {
        // On hit: set block to MRU, increment SHiP outcome counter
        rrpv[set][way] = 0;
        if (ship_table[block_signature[set][way]] < 3)
            ++ship_table[block_signature[set][way]];
        // Reset dead-block counter
        dead_counter[set][way] = 0;
        return;
    }

    // On fill: set block signature
    block_signature[set][way] = sig;

    // SHiP: if outcome counter high, insert at MRU; else at distant RRPV
    if (ship_table[sig] >= 2)
        rrpv[set][way] = 0; // MRU
    else
        rrpv[set][way] = 3; // distant

    // Dead-block counter: reset on fill
    dead_counter[set][way] = 0;

    // On victim eviction: if block was not reused, decrement SHiP outcome
    // (i.e., if dead_counter == 3, treat as not reused)
    if (dead_counter[set][way] == 3 && ship_table[block_signature[set][way]] > 0)
        --ship_table[block_signature[set][way]];
}

// --- Dead-block counter update ---
// Called externally every N accesses (e.g., every 4096 fills)
void DecayDeadCounters() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_counter[set][way] < 3)
                ++dead_counter[set][way];
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SDH Policy: SHiP-lite Signature Insertion + Dead-block Victim Selection\n";
}
void PrintStats_Heartbeat() {}