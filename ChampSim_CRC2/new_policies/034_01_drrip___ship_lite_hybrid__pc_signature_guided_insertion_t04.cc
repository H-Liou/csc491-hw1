#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//--------------------------------------------
// RRIP bits: 2 per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

//--------------------------------------------
// DRRIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;
uint8_t is_leader_set[LLC_SETS]; // 0: normal, 1: SRRIP leader, 2: BRRIP leader

//--------------------------------------------
// SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_reuse[LLC_SETS][SHIP_SIG_ENTRIES]; // 2-bit counter per set/signature
uint8_t ship_sig[LLC_SETS][LLC_WAYS];           // 6-bit PC signature per block

//--------------------------------------------
// Helper: hash PC to signature
inline uint8_t GetSignature(uint64_t PC) {
    // Use lower bits of CRC32 for mixing
    return champsim_crc32(PC) & (SHIP_SIG_ENTRIES - 1);
}

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_reuse, 1, sizeof(ship_reuse)); // Start neutral
    memset(ship_sig, 0, sizeof(ship_sig));
    memset(is_leader_set, 0, sizeof(is_leader_set));
    // Assign leader sets (first half SRRIP, second half BRRIP)
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = 1; // SRRIP leader
        is_leader_set[LLC_SETS - 1 - i] = 2; // BRRIP leader
    }
    PSEL = PSEL_MAX / 2;
}

//--------------------------------------------
// Find victim in the set (RRIP)
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
            rrpv[set][way]++;
    }
    return 0; // Should not reach
}

//--------------------------------------------
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
    //--- Get PC signature
    uint8_t sig = GetSignature(PC);

    //--- On hit: promote and update reuse counter
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_reuse[set][sig] < 3) ship_reuse[set][sig]++;
    } else {
        //--- On miss: choose insertion depth
        uint8_t ins_rrpv = 2; // Default: "long" (SRRIP)
        // DRRIP: choose policy for this set
        uint8_t policy = 0; // 0: SRRIP, 1: BRRIP
        if (is_leader_set[set] == 1) policy = 0;
        else if (is_leader_set[set] == 2) policy = 1;
        else policy = (PSEL >= PSEL_MAX / 2) ? 0 : 1;

        // SHiP-lite: dead-block prediction
        if (ship_reuse[set][sig] == 0) {
            ins_rrpv = 3; // Insert at "distant" if signature is dead
        } else if (policy == 1) {
            // BRRIP: 1/32 probability insert at "long"
            if ((rand() & 31) == 0) ins_rrpv = 2;
            else ins_rrpv = 3;
        }

        rrpv[set][way] = ins_rrpv;
        ship_sig[set][way] = sig;
    }

    //--- On eviction: update SHiP-lite reuse counter
    if (!hit) {
        uint8_t victim_sig = ship_sig[set][way];
        // If block was not reused before eviction, decrement
        if (ship_reuse[set][victim_sig] > 0) ship_reuse[set][victim_sig]--;
    }

    //--- DRRIP set-dueling: update PSEL if leader set
    if (is_leader_set[set] == 1) { // SRRIP leader
        if (hit && PSEL < PSEL_MAX) PSEL++;
    } else if (is_leader_set[set] == 2) { // BRRIP leader
        if (hit && PSEL > 0) PSEL--;
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + SHiP-lite Hybrid: Final statistics." << std::endl;
    // Optionally, print PSEL and average reuse
    uint64_t total_reuse = 0, total_entries = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
            total_reuse += ship_reuse[set][i];
            total_entries++;
        }
    std::cout << "Mean SHiP-lite reuse: " << (double)total_reuse / total_entries << std::endl;
    std::cout << "Final PSEL: " << PSEL << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL and reuse histogram
}