#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//--- DRRIP globals ---
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2; // 10-bit selector

// Tag leader sets for SRRIP/BRRIP
bool is_sr_leader_set[LLC_SETS];
bool is_br_leader_set[LLC_SETS];

//--- RRIP bits: 2 per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

//--- SHiP-lite: per-set, 32-entry table of 4-bit PC signatures, each with 2-bit reuse counter
#define SHIP_SIG_BITS 4
#define SHIP_TABLE_SIZE 32
uint16_t ship_sig_table[LLC_SETS][SHIP_TABLE_SIZE]; // 4-bit PC sig per entry
uint8_t ship_reuse_ctr[LLC_SETS][SHIP_TABLE_SIZE];  // 2-bit counter per entry

//--- Simple hash for signature index
inline uint32_t sig_index(uint64_t PC) {
    return (PC ^ (PC >> SHIP_SIG_BITS)) & (SHIP_TABLE_SIZE - 1);
}
inline uint16_t sig_value(uint64_t PC) {
    return (PC >> 2) & 0xF;
}

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All blocks distant
    memset(ship_sig_table, 0, sizeof(ship_sig_table));
    memset(ship_reuse_ctr, 0, sizeof(ship_reuse_ctr));

    // Select leader sets for SRRIP and BRRIP
    memset(is_sr_leader_set, 0, sizeof(is_sr_leader_set));
    memset(is_br_leader_set, 0, sizeof(is_br_leader_set));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_sr_leader_set[i] = true; // low set indices: SRRIP leaders
        is_br_leader_set[LLC_SETS - 1 - i] = true; // high set indices: BRRIP leaders
    }
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
    //--- SHiP-lite index
    uint32_t sig_idx = sig_index(PC);
    uint16_t sig_val = sig_value(PC);

    //--- Learn reuse: update counter on hit
    if (hit) {
        if (ship_sig_table[set][sig_idx] == sig_val) {
            if (ship_reuse_ctr[set][sig_idx] < 3)
                ship_reuse_ctr[set][sig_idx]++;
        } else {
            ship_sig_table[set][sig_idx] = sig_val;
            ship_reuse_ctr[set][sig_idx] = 1;
        }
        rrpv[set][way] = 0; // promote on hit
        return;
    }

    //--- On miss: determine insertion depth
    // DRRIP set-dueling: pick SRRIP or BRRIP based on leaders & PSEL
    bool use_brrip = false;
    if (is_sr_leader_set[set]) use_brrip = false;
    else if (is_br_leader_set[set]) use_brrip = true;
    else use_brrip = (PSEL < (PSEL_MAX / 2));

    // SHiP-lite: reuse counter guides insertion
    uint8_t reuse = (ship_sig_table[set][sig_idx] == sig_val) ? ship_reuse_ctr[set][sig_idx] : 0;

    if (reuse >= 2) {
        // High reuse: insert at RRPV=0 (long retention)
        rrpv[set][way] = 0;
    } else {
        // Low/no reuse: combine DRRIP insertion
        if (use_brrip)
            rrpv[set][way] = 3; // BRRIP: insert distant
        else
            rrpv[set][way] = 2; // SRRIP: insert intermediate
    }

    //--- Update SHiP-lite table
    ship_sig_table[set][sig_idx] = sig_val;
    ship_reuse_ctr[set][sig_idx] = (reuse > 0) ? (reuse - 1) : 0; // slight decay on miss

    //--- Update PSEL for leader sets
    if (is_sr_leader_set[set]) {
        if (hit && rrpv[set][way] == 0) // hit on SRRIP leader
            if (PSEL < PSEL_MAX) PSEL++;
    } else if (is_br_leader_set[set]) {
        if (hit && rrpv[set][way] == 0) // hit on BRRIP leader
            if (PSEL > 0) PSEL--;
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + SHiP-Lite Hybrid: Final statistics." << std::endl;
    std::cout << "PSEL final value: " << PSEL << " / " << PSEL_MAX << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL
    std::cout << "[Heartbeat] PSEL=" << PSEL << std::endl;
}