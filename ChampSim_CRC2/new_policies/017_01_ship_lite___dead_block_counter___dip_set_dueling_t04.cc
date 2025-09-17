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

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- Dead-block counter: 2-bit per block ---
uint8_t dead_block_counter[LLC_SETS][LLC_WAYS];

// --- Periodic decay for dead-block counters ---
#define DEADBLOCK_DECAY_INTERVAL 8192
uint64_t access_counter = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant
    memset(is_leader_lip, 0, sizeof(is_leader_lip));
    memset(is_leader_bip, 0, sizeof(is_leader_bip));
    memset(dead_block_counter, 0, sizeof(dead_block_counter));
    PSEL = 512;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_lip[s] = true, is_leader_bip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_lip[s] = false, is_leader_bip[s] = true;
        else
            is_leader_lip[s] = false, is_leader_bip[s] = false;
    }
    access_counter = 0;
}

// --- Find victim: standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
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
    // --- Periodic decay of dead-block counters ---
    if ((access_counter % DEADBLOCK_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_block_counter[s][w] > 0)
                    dead_block_counter[s][w]--;
    }

    // --- SHiP signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: update SHiP outcome, set RRPV=0, reset dead-block counter ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = 0;
        dead_block_counter[set][way] = 0;
        // Set-dueling update
        if (is_leader_lip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_bip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- DIP policy selection: LIP or BIP ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL >= 512);

    // --- Decide insertion RRPV ---
    uint8_t ins_rrpv = 0; // MRU default
    if (use_lip) {
        ins_rrpv = 3; // LIP: always insert at LRU
    } else {
        // BIP: insert at LRU with low probability (1/32), else MRU
        ins_rrpv = ((rand() % 32) == 0) ? 3 : 0;
    }

    // --- SHiP outcome: for high-reuse sigs, insert at MRU ---
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;

    // --- Dead-block counter: if block predicted dead, insert at LRU ---
    if (dead_block_counter[set][way] >= 2)
        ins_rrpv = 3;

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;
    dead_block_counter[set][way] = 0; // reset on fill

    // --- On eviction: update SHiP outcome for victim block, increment dead-block counter ---
    uint8_t victim_sig = block_sig[set][way];
    if (ins_rrpv == 3 && ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;
    // Increment dead-block counter for victim
    if (dead_block_counter[set][way] < 3)
        dead_block_counter[set][way]++;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Dead-Block Counter + DIP Set-Dueling: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, SHiP histogram, dead-block counter stats
}