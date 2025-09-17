#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: set-dueling, SRRIP/BRRIP, 10-bit PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // Neutral start

inline bool is_srrip_leader(uint32_t set) { return set < 32; }
inline bool is_brrip_leader(uint32_t set) { return set >= 32 && set < 64; }
inline bool is_follower(uint32_t set)     { return set >= NUM_LEADER_SETS; }

// --- SHiP-lite: 6-bit PC signature, 2-bit counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block approximation: 1-bit per block, global decay every N accesses ---
uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 0: alive, 1: dead
uint64_t global_access_ctr = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_block, 0, sizeof(dead_block));
    PSEL = (1 << (PSEL_BITS - 1));
    global_access_ctr = 0;
}

// --- Find victim: prefer blocks marked dead, else SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // 1. Prefer blocks marked dead
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_block[set][way] == 1)
            return way;

    // 2. If no dead block, use SRRIP: victim with RRPV==3
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
    global_access_ctr++;

    // --- SHiP-lite signature ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- Dead-block approximation ---
    if (!hit) {
        if (dead_block[set][way] < 1)
            dead_block[set][way]++;
    } else {
        dead_block[set][way] = 0; // block reused, mark alive
    }

    // --- Periodic decay of dead-block counters (every 10,000 accesses) ---
    if ((global_access_ctr & 0x2710) == 0) { // 0x2710 == 10000
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_block[s][w] > 0)
                    dead_block[s][w]--;
    }

    // --- On hit: update SHiP predictor and RRPV ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = 0;
        return;
    }

    // --- Decide insertion policy: DRRIP + SHiP-lite ---
    uint8_t ins_rrpv = 3; // default distant

    // 1. Set-dueling: SRRIP/BRRIP
    bool sr_insert = false;
    if (is_srrip_leader(set)) sr_insert = true;
    else if (is_brrip_leader(set)) sr_insert = false;
    else sr_insert = (PSEL >= (1 << (PSEL_BITS - 1)));

    // 2. SHiP-lite: MRU insert if signature is reused
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;
    else if (sr_insert)
        ins_rrpv = 2; // SRRIP: insert with RRPV=2
    else {
        // BRRIP: insert with RRPV=2 only 1/32 fills, else 3
        static uint32_t brrip_ctr = 0;
        brrip_ctr++;
        if ((brrip_ctr & 0x1F) == 0)
            ins_rrpv = 2;
        else
            ins_rrpv = 3;
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;
    dead_block[set][way] = 0; // New block: not dead

    // --- On eviction: update SHiP predictor for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;

    // --- DRRIP set-dueling: update PSEL on leader set fills ---
    if (is_srrip_leader(set)) {
        if (hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        else if (!hit && PSEL > 0) PSEL--;
    } else if (is_brrip_leader(set)) {
        if (hit && PSEL > 0) PSEL--;
        else if (!hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP-SHiP Hybrid + Dead-Block Decay: Final statistics." << std::endl;
    uint32_t reused_cnt = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i] >= 2) reused_cnt++;
    std::cout << "SHiP-lite predictor: " << reused_cnt << " signatures predicted reused." << std::endl;

    uint32_t dead_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w])
                dead_cnt++;
    std::cout << "Dead blocks at end: " << dead_cnt << "/" << (LLC_SETS * LLC_WAYS) << std::endl;

    std::cout << "DRRIP PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print dead block count and reuse histogram
}