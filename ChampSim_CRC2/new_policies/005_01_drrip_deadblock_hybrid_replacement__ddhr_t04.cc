#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits per line
uint8_t deadblock[LLC_SETS][LLC_WAYS];   // 2 bits per line

// DRRIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1));  // Middle value
bool is_leader_sr[LLC_SETS];             // true if SRRIP leader
bool is_leader_br[LLC_SETS];             // true if BRRIP leader

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));        // RRPV max
    memset(deadblock, 0, sizeof(deadblock)); // Dead-block counters
    memset(is_leader_sr, 0, sizeof(is_leader_sr));
    memset(is_leader_br, 0, sizeof(is_leader_br));
    // Assign leader sets (even: SRRIP, odd: BRRIP)
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = (i * LLC_SETS) / NUM_LEADER_SETS;
        if (i % 2 == 0)
            is_leader_sr[set] = true;
        else
            is_leader_br[set] = true;
    }
    PSEL = (1 << (PSEL_BITS - 1)); // Reset to middle
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
    // --- Dead-block predictor ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        deadblock[set][way] = 0; // Reset dead-block counter
        return;
    } else {
        // On fill, increment dead-block counter for victim
        uint8_t &dbc = deadblock[set][way];
        if (dbc < 3) ++dbc;
    }

    // --- DRRIP set-dueling: decide insertion policy ---
    bool sr_leader = is_leader_sr[set];
    bool br_leader = is_leader_br[set];
    bool use_brrip = false;

    if (sr_leader)
        use_brrip = false;
    else if (br_leader)
        use_brrip = true;
    else
        use_brrip = (PSEL < (1 << (PSEL_BITS - 1))); // Lower PSEL: favor BRRIP

    // --- Dead-block: if counter saturated, always insert at distant RRPV ---
    if (deadblock[set][way] == 3) {
        rrpv[set][way] = 3; // Distant RRPV
    } else {
        // DRRIP insertion
        if (use_brrip) {
            // BRRIP: insert at RRPV=2 (long re-reference interval) most of the time
            if ((rand() & 0x7) == 0) // 1/8 fills at MRU
                rrpv[set][way] = 0;
            else
                rrpv[set][way] = 2;
        } else {
            // SRRIP: insert at RRPV=2 always
            rrpv[set][way] = 2;
        }
    }

    // --- Update PSEL on leader sets ---
    if (sr_leader && !hit) {
        if (PSEL < ((1 << PSEL_BITS) - 1)) ++PSEL;
    }
    if (br_leader && !hit) {
        if (PSEL > 0) --PSEL;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DDHR Policy: DRRIP set-dueling + per-line dead-block predictor\n";
    std::cout << "PSEL final value: " << PSEL << std::endl;
}
void PrintStats_Heartbeat() {}