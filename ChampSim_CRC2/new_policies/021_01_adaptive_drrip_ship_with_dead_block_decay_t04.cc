#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP set-dueling: leader sets, PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // start neutral

inline bool is_srrip_leader(uint32_t set) { return set < 32; }
inline bool is_brrip_leader(uint32_t set) { return set >= 32 && set < 64; }
inline bool is_follower(uint32_t set)   { return set >= NUM_LEADER_SETS; }

// --- SHiP-lite: 6-bit PC signature, 2-bit reuse counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating reuse counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block counter: 2-bit per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// --- Periodic decay for dead-block counters ---
uint64_t global_access_ctr = 0;
#define DECAY_PERIOD 4096

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant
    memset(dead_ctr, 0, sizeof(dead_ctr));
    PSEL = (1 << (PSEL_BITS - 1));
    global_access_ctr = 0;
}

// --- Find victim: dead-block aware SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with dead_ctr == 3 (likely dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
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
    global_access_ctr++;

    // --- Periodic decay for dead-block counters ---
    if ((global_access_ctr & (DECAY_PERIOD-1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }

    // --- SHiP-lite signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: update SHiP-lite predictor, set RRPV=0, reset dead-block counter ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = 0;
        dead_ctr[set][way] = 0;
        return;
    }

    // --- Decide insertion policy: DRRIP + SHiP + dead-block ---
    uint8_t ins_rrpv = 3; // default distant

    // 1. Dead-block: if dead_ctr==3, bypass (insert distant)
    if (dead_ctr[set][way] == 3) {
        ins_rrpv = 3;
    } else {
        // 2. Leader sets: DRRIP set-dueling
        bool srrip = false;
        if (is_srrip_leader(set))      srrip = true;
        else if (is_brrip_leader(set)) srrip = false;
        else                           srrip = (PSEL >= (1 << (PSEL_BITS - 1)));

        // 3. SHiP-lite: bias toward MRU if signature is reused
        if (ship_table[sig] >= 2)
            ins_rrpv = 0;
        else if (srrip)
            ins_rrpv = 3; // SRRIP: always distant
        else {
            // BRRIP: MRU only 1/32 fills; else distant
            static uint32_t brrip_ctr = 0;
            brrip_ctr++;
            if ((brrip_ctr & 0x1F) == 0)
                ins_rrpv = 0;
            else
                ins_rrpv = 3;
        }
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP-lite predictor for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ship_table[victim_sig] > 0) ship_table[victim_sig]--; // decay if evicted without reuse

    // --- Dead-block counter: increment if evicted without reuse ---
    if (!hit && dead_ctr[set][way] < 3)
        dead_ctr[set][way]++;

    // --- DRRIP set-dueling: update PSEL on leader set fills ---
    // If hit: reward policy of leader set; else, penalize
    if (is_srrip_leader(set)) {
        if (hit && PSEL < ((1<<PSEL_BITS)-1)) PSEL++;
        else if (!hit && PSEL > 0) PSEL--;
    } else if (is_brrip_leader(set)) {
        if (hit && PSEL > 0) PSEL--;
        else if (!hit && PSEL < ((1<<PSEL_BITS)-1)) PSEL++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Adaptive DRRIP-SHiP+DeadBlock: Final statistics." << std::endl;
    uint32_t reused_cnt = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i] >= 2) reused_cnt++;
    std::cout << "SHiP-lite predictor: " << reused_cnt << " signatures predicted reused." << std::endl;
    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] == 3) dead_blocks++;
    std::cout << "Dead blocks detected: " << dead_blocks << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "DRRIP PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print dead block count and SHiP reuse histogram
}