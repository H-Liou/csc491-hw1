#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//--------------------------------------------
// SHiP-lite metadata: 4-bit PC signature, 2-bit reuse counter
#define SHIP_SIG_BITS 4
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS) // 16
uint8_t ship_reuse[LLC_SETS][SHIP_TABLE_SIZE]; // 2 bits per signature per set
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 4 bits per block

// RRIP bits: 2 per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

//--------------------------------------------
// DIP metadata: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t psel = PSEL_MAX / 2; // 10-bit saturating counter

// Leader set selection: first 32 sets for LIP, next 32 for BIP
inline bool is_lip_leader(uint32_t set) { return set < NUM_LEADER_SETS / 2; }
inline bool is_bip_leader(uint32_t set) { return set >= NUM_LEADER_SETS / 2 && set < NUM_LEADER_SETS; }

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Distant for all blocks
    memset(ship_reuse, 1, sizeof(ship_reuse)); // Start at weak reuse
    memset(block_sig, 0, sizeof(block_sig));
    psel = PSEL_MAX / 2;
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
    //--- SHiP-lite signature
    uint8_t sig = ((PC >> 2) ^ set) & SHIP_SIG_MASK;
    uint8_t reuse_ctr = ship_reuse[set][sig];

    //--- DIP: Determine insertion policy for this set
    bool use_lip = false, use_bip = false;
    if (is_lip_leader(set)) use_lip = true;
    else if (is_bip_leader(set)) use_bip = true;
    else use_lip = (psel < (PSEL_MAX / 2)); // PSEL < midpoint: favor LIP, else BIP

    //--- SHiP-lite guides insertion depth
    uint8_t ins_rrpv = 3; // Default: distant (LIP)
    if (reuse_ctr >= 2)
        ins_rrpv = 1; // Likely reused soon
    else if (reuse_ctr == 1)
        ins_rrpv = 2; // Medium

    //--- DIP insertion logic
    if (use_lip) {
        ins_rrpv = 3; // Always insert at distant
    } else if (use_bip) {
        // BIP: Insert at distant except 1/32 times at RRPV=0
        static uint32_t bip_ctr = 0;
        if ((bip_ctr++ & 0x1F) == 0)
            ins_rrpv = 0;
        else
            ins_rrpv = 3;
    }
    // Else: use SHiP-lite guided insertion for non-leader sets

    //--- On hit: promote & reinforce signature
    if (hit) {
        rrpv[set][way] = 0;
        uint8_t sig_hit = block_sig[set][way];
        if (ship_reuse[set][sig_hit] < 3)
            ship_reuse[set][sig_hit]++;
        // DIP: Update PSEL for leader sets
        if (is_lip_leader(set) && hit) {
            if (psel < PSEL_MAX) psel++;
        } else if (is_bip_leader(set) && hit) {
            if (psel > 0) psel--;
        }
    } else {
        rrpv[set][way] = ins_rrpv;
        block_sig[set][way] = sig;
        // If block replaced, penalize old signature
        uint8_t victim_sig = block_sig[set][way];
        if (ship_reuse[set][victim_sig] > 0)
            ship_reuse[set][victim_sig]--;
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + DIP Hybrid: Final statistics." << std::endl;
    std::cout << "PSEL value: " << psel << " (max " << PSEL_MAX << ")" << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL value
}