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
uint8_t ship_ctr[SIG_TABLE_SIZE];           // 2-bit outcome counter per signature

// --- Dead-block approximation ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];       // 2-bit dead-block counter per block

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Set-dueling for SHiP vs Dead-block ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_ship[LLC_SETS];      // 1 if SHiP leader
uint8_t is_leader_dbr[LLC_SETS];       // 1 if Dead-block leader

// Periodic decay epoch for dead-block counters
#define DBR_DECAY_EPOCH 4096
uint64_t access_count = 0;

void InitReplacementState() {
    // Initialize RRIP, SHiP-lite, dead-block
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            dead_ctr[set][way] = 0;
        }
        is_leader_ship[set] = 0;
        is_leader_dbr[set] = 0;
    }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        ship_ctr[i] = 1;
    // First DUEL_LEADER_SETS sets are SHiP-leader, next DUEL_LEADER_SETS are DBR-leader
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_ship[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_dbr[i] = 1;
    access_count = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection
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
    access_count++;
    if (access_count % DBR_DECAY_EPOCH == 0)
        DecayDeadBlockCounters();

    // --- Signature extraction ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x3F)) & ((1 << SIG_BITS)-1);

    // --- SHiP-lite update ---
    uint8_t old_sig = block_sig[set][way];
    if (hit) {
        // On hit, reward signature and dead-block counter
        if (ship_ctr[old_sig] < 3)
            ship_ctr[old_sig]++;
        rrpv[set][way] = 0; // MRU
        if (dead_ctr[set][way] > 0)
            dead_ctr[set][way]--;
    } else {
        // On eviction, penalize signature if not reused
        if (ship_ctr[old_sig] > 0)
            ship_ctr[old_sig]--;
        // New block: record signature and reset dead-block counter
        block_sig[set][way] = sig;
        dead_ctr[set][way] = 0;

        // --- Insertion policy selection ---
        bool use_ship;
        if (is_leader_ship[set])
            use_ship = true;
        else if (is_leader_dbr[set])
            use_ship = false;
        else
            use_ship = (psel < (1 << (PSEL_BITS-1)));

        // Dead-block logic: if dead_ctr is high (>=2), insert at distant RRPV or bypass
        if (!use_ship && dead_ctr[set][way] >= 2) {
            rrpv[set][way] = 3; // Bypass
            // For leader sets, update PSEL
            if (is_leader_dbr[set] && !hit)
                if (psel < ((1<<PSEL_BITS)-1)) psel++;
        }
        // SHiP logic: if hot signature, insert MRU; else distant
        else if (use_ship && ship_ctr[sig] >= 2) {
            rrpv[set][way] = 0;
            if (is_leader_ship[set] && !hit)
                if (psel > 0) psel--;
        }
        // Otherwise: insert at distant RRPV
        else {
            rrpv[set][way] = 2;
        }
    }
    // On every miss, increment dead_ctr for the evicted block (if not reused)
    if (!hit && dead_ctr[set][way] < 3)
        dead_ctr[set][way]++;
}

void PrintStats() {
    int hot = 0, cold = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (ship_ctr[i] >= 2) hot++;
        else cold++;
    }
    std::cout << "SHiP-DBR: Hot PC signatures: " << hot << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SHiP-DBR: Cold PC signatures: " << cold << std::endl;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] >= 2) dead_blocks++;
    std::cout << "SHiP-DBR: Dead blocks (ctr>=2): " << dead_blocks << " / " << (LLC_SETS*LLC_WAYS) << std::endl;
}

void PrintStats_Heartbeat() {
    int hot = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        if (ship_ctr[i] >= 2) hot++;
    std::cout << "SHiP-DBR: Hot signature count: " << hot << std::endl;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] >= 2) dead_blocks++;
    std::cout << "SHiP-DBR: Dead blocks: " << dead_blocks << std::endl;
}