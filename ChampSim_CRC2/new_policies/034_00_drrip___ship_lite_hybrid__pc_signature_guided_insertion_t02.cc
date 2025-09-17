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
// DRRIP set-dueling: 64 leader sets (32 SRRIP, 32 BRRIP)
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023 // 10 bits
uint16_t PSEL = PSEL_MAX / 2; // Global policy selector

// Leader set mapping
bool IsSRRIPLeader(uint32_t set) { return (set % NUM_LEADER_SETS) < (NUM_LEADER_SETS / 2); }
bool IsBRRIPLeader(uint32_t set) { return (set % NUM_LEADER_SETS) >= (NUM_LEADER_SETS / 2); }

//--------------------------------------------
// SHiP-lite: 4-bit PC signature per block, 2-bit outcome counter per signature
#define SIG_BITS 4
#define SIG_MASK ((1 << SIG_BITS) - 1)
#define SIG_TABLE_SIZE (1 << SIG_BITS)
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 4 bits per block
uint8_t sig_outcome[SIG_TABLE_SIZE];   // 2 bits per signature

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All blocks distant
    memset(block_sig, 0, sizeof(block_sig));
    memset(sig_outcome, 1, sizeof(sig_outcome)); // Start neutral
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
    // Standard RRIP victim selection
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
    //--- Compute PC signature
    uint8_t sig = (PC ^ (PC >> 4)) & SIG_MASK;

    //--- Update SHiP-lite outcome counter
    if (hit) {
        if (sig_outcome[sig] < 3) sig_outcome[sig]++;
        rrpv[set][way] = 0; // Promote on hit
    } else {
        if (sig_outcome[sig] > 0) sig_outcome[sig]--;
        //--- DRRIP insertion policy
        bool sr_leader = IsSRRIPLeader(set);
        bool br_leader = IsBRRIPLeader(set);
        bool use_brrip = false;
        if (sr_leader) use_brrip = false;
        else if (br_leader) use_brrip = true;
        else use_brrip = (PSEL < (PSEL_MAX / 2)); // PSEL < 512: BRRIP, else SRRIP

        //--- SHiP-lite guided insertion
        if (sig_outcome[sig] >= 2) {
            rrpv[set][way] = 0; // High reuse: insert at MRU
        } else {
            rrpv[set][way] = use_brrip ? 3 : 2; // BRRIP: mostly distant, SRRIP: long
        }

        //--- Update PSEL for leader sets
        if (sr_leader && hit) { if (PSEL < PSEL_MAX) PSEL++; }
        if (br_leader && hit) { if (PSEL > 0) PSEL--; }
    }

    //--- Store signature for block
    block_sig[set][way] = sig;
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + SHiP-lite Hybrid: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << " (SRRIP if high, BRRIP if low)" << std::endl;
    // Optionally, print signature outcome histogram
    uint32_t high_reuse = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_outcome[i] >= 2) high_reuse++;
    std::cout << "High-reuse signatures: " << high_reuse << " / " << SIG_TABLE_SIZE << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL and high-reuse signature count
}