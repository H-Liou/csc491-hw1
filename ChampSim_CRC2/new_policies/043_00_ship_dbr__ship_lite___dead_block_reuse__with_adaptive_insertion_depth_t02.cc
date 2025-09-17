#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 64
uint8_t block_sig[LLC_SETS][LLC_WAYS];      // Per-block signature
uint8_t ship_ctr[SIG_TABLE_SIZE];           // 2-bit saturating outcome counter per signature

// --- Dead-block approximation ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per-block dead-block counter

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Set-dueling for SRRIP vs BRRIP ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_srrip[LLC_SETS];      // 1 if SRRIP leader
uint8_t is_leader_brrip[LLC_SETS];      // 1 if BRRIP leader

// --- Dead-block periodic decay ---
uint64_t access_counter = 0;
#define DEAD_DECAY_PERIOD 4096

void InitReplacementState() {
    // Initialize RRIP, SHiP, dead-block counters
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            dead_ctr[set][way] = 2; // Start as "possibly live"
        }
        is_leader_srrip[set] = 0;
        is_leader_brrip[set] = 0;
    }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        ship_ctr[i] = 1;
    // First DUEL_LEADER_SETS sets are SRRIP-leader, next DUEL_LEADER_SETS are BRRIP-leader
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_srrip[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_brrip[i] = 1;
    access_counter = 0;
}

// Find victim in the set (classic RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
    }
}

// Periodic decay of dead-block counters
void DecayDeadBlockCounters() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] > 0)
                dead_ctr[set][way]--;
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
    if ((access_counter % DEAD_DECAY_PERIOD) == 0)
        DecayDeadBlockCounters();

    // --- Signature extraction ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x3F)) & ((1 << SIG_BITS)-1);

    // --- SHiP-lite update ---
    uint8_t old_sig = block_sig[set][way];
    if (hit) {
        // On hit, reward signature and dead-block counter
        if (ship_ctr[old_sig] < 3)
            ship_ctr[old_sig]++;
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
        rrpv[set][way] = 0; // MRU
    } else {
        // On eviction, penalize signature if not reused
        if (ship_ctr[old_sig] > 0)
            ship_ctr[old_sig]--;
        // New block: record signature, reset dead-block counter
        block_sig[set][way] = sig;
        dead_ctr[set][way] = 2;

        // --- Insertion policy selection ---
        bool use_brrip;
        if (is_leader_srrip[set])
            use_brrip = false;
        else if (is_leader_brrip[set])
            use_brrip = true;
        else
            use_brrip = (psel < (1 << (PSEL_BITS-1)));

        // Dead-block + cold signature: BRRIP distant insertion (RRPV=3)
        if (dead_ctr[set][way] == 0 && ship_ctr[sig] <= 1) {
            rrpv[set][way] = 3;
            // For leader sets, update PSEL
            if (is_leader_brrip[set] && !hit)
                if (psel < ((1<<PSEL_BITS)-1)) psel++;
        }
        // Hot signature or reused block: SRRIP MRU insertion (RRPV=0)
        else if (ship_ctr[sig] >= 2 || dead_ctr[set][way] >= 2) {
            rrpv[set][way] = 0;
            if (is_leader_srrip[set] && !hit)
                if (psel > 0) psel--;
        }
        // Otherwise: SRRIP distant insertion (RRPV=2)
        else {
            rrpv[set][way] = use_brrip ? 3 : 2;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot = 0, cold = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (ship_ctr[i] >= 2) hot++;
        else cold++;
    }
    std::cout << "SHiP-DBR: Hot PC signatures: " << hot << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SHiP-DBR: Cold PC signatures: " << cold << std::endl;
    int dead = 0, live = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 0) dead++;
            else live++;
    std::cout << "SHiP-DBR: Dead blocks: " << dead << " / " << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "SHiP-DBR: Live blocks: " << live << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int hot = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        if (ship_ctr[i] >= 2) hot++;
    std::cout << "SHiP-DBR: Hot signature count: " << hot << std::endl;
    int dead = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 0) dead++;
    std::cout << "SHiP-DBR: Dead blocks: " << dead << std::endl;
}