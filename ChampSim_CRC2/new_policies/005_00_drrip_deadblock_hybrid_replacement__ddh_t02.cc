#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];           // 2 bits per line
uint8_t deadblock[LLC_SETS][LLC_WAYS];      // 2 bits per line

// DRRIP set-dueling: 32 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1));     // Start at midpoint

bool is_sr_leader(uint32_t set) { return set % LLC_SETS < NUM_LEADER_SETS; }
bool is_br_leader(uint32_t set) { return set % LLC_SETS >= LLC_SETS-NUM_LEADER_SETS; }

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));          // 2-bit RRPV, init to max
    memset(deadblock, 0, sizeof(deadblock));// 2-bit dead-block counter
    psel = (1 << (PSEL_BITS - 1));
}

// --- Victim selection (SRRIP) ---
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
    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        if (deadblock[set][way] > 0) --deadblock[set][way]; // decay deadness on reuse
        return;
    }

    // --- On fill ---
    // DRRIP insertion policy selection
    bool sr_leader = is_sr_leader(set);
    bool br_leader = is_br_leader(set);
    bool use_brrip = false;

    if (sr_leader) use_brrip = false;
    else if (br_leader) use_brrip = true;
    else use_brrip = (psel < (1 << (PSEL_BITS - 1)));

    // Dead-block bias: if predicted dead, always insert at distant RRPV
    if (deadblock[set][way] == 3) {
        rrpv[set][way] = 3; // distant
    } else {
        // DRRIP insertion: SRRIP (RRPV=2) or BRRIP (RRPV=3 with 1/32 probability)
        if (use_brrip) {
            rrpv[set][way] = (rand() % 32 == 0) ? 2 : 3;
        } else {
            rrpv[set][way] = 2;
        }
    }

    // On eviction, increment dead-block counter
    deadblock[set][way] = std::min(deadblock[set][way]+1, (uint8_t)3);

    // --- DRRIP set-dueling feedback ---
    if (sr_leader || br_leader) {
        // If fill was a hit (reuse), increment PSEL for SRRIP, decrement for BRRIP
        if (hit) {
            if (sr_leader && psel < ((1 << PSEL_BITS)-1)) ++psel;
            if (br_leader && psel > 0) --psel;
        }
    }
}

// --- Periodic decay of dead-block counters (every N million accesses) ---
void DecayDeadBlockCounters() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (deadblock[set][way] > 0) --deadblock[set][way];
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DDH Policy: DRRIP (set-dueling) + Dead-block Approximation Hybrid\n";
    std::cout << "PSEL = " << psel << "\n";
}
void PrintStats_Heartbeat() {}