#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP: 32 leader sets for LIP, 32 for BIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- PC Dead-block predictor: 6-bit PC signature, 2-bit dead counter ---
#define PC_SIG_BITS 6
#define PC_SIG_ENTRIES (1 << PC_SIG_BITS)
uint8_t pc_dead_table[PC_SIG_ENTRIES]; // 2-bit saturating counter

// --- Per-block temporal dead-block counter: 2 bits per block ---
uint8_t block_dead_counter[LLC_SETS][LLC_WAYS];

// --- Per-block PC signature ---
uint8_t block_sig[LLC_SETS][LLC_WAYS];

// --- Decay interval ---
#define DEAD_DECAY_INTERVAL 8192
uint64_t fill_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(is_leader_lip, 0, sizeof(is_leader_lip));
    memset(is_leader_bip, 0, sizeof(is_leader_bip));
    memset(pc_dead_table, 0, sizeof(pc_dead_table));
    memset(block_dead_counter, 0, sizeof(block_dead_counter));
    memset(block_sig, 0, sizeof(block_sig));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_lip[s] = true, is_leader_bip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_lip[s] = false, is_leader_bip[s] = true;
        else
            is_leader_lip[s] = false, is_leader_bip[s] = false;
    }
    PSEL = 512;
    fill_count = 0;
}

// --- Find victim: LRU (for DIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Choose the block with the lowest dead-counter first (prefer dead blocks)
    uint32_t victim = 0;
    uint8_t min_dead = block_dead_counter[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (block_dead_counter[set][way] < min_dead) {
            min_dead = block_dead_counter[set][way];
            victim = way;
        }
    }
    return victim;
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
    // --- PC signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (PC_SIG_ENTRIES - 1);

    // --- On hit: increment dead counter, update PC dead table ---
    if (hit) {
        if (block_dead_counter[set][way] < 3)
            block_dead_counter[set][way]++;
        block_sig[set][way] = sig;
        if (pc_dead_table[sig] > 0)
            pc_dead_table[sig]--;
        // DIP set-dueling update
        if (is_leader_lip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_bip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- Dead-block prediction for bypass ---
    bool bypass = false;
    // If PC dead-table is high (>=2), or block victim dead-counter is 0, bypass
    if (pc_dead_table[sig] >= 2)
        bypass = true;
    else if (block_dead_counter[set][way] == 0)
        bypass = true;

    // --- DIP insertion depth selection ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL >= 512);

    // --- Insert block ---
    if (bypass) {
        // Do not insert, treat as dead
        block_dead_counter[set][way] = 0;
        block_sig[set][way] = sig;
        if (pc_dead_table[sig] < 3)
            pc_dead_table[sig]++;
        // No DIP update for bypassed fills
        return;
    } else {
        // Insert at MRU for LIP, else BIP: MRU with low probability, else LRU
        if (use_lip) {
            block_dead_counter[set][way] = 3; // live
        } else {
            block_dead_counter[set][way] = ((rand() % 32) == 0) ? 3 : 0;
        }
        block_sig[set][way] = sig;
        // Update PC dead-table: if inserted at LRU, increase deadness
        if (block_dead_counter[set][way] == 0 && pc_dead_table[sig] < 3)
            pc_dead_table[sig]++;
    }

    // --- Periodic dead-block decay ---
    fill_count++;
    if ((fill_count % DEAD_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (block_dead_counter[s][w] > 0)
                    block_dead_counter[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DIP-LIP/BIP + PC-Temporal Dead-Block Bypass: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, dead-block histogram, bypass stats
}