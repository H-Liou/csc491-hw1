#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP Set-Dueling Parameters ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t psel = PSEL_MAX / 2;
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: normal

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant
    memset(ship_table, 1, sizeof(ship_table)); // neutral bias
    memset(block_sig, 0, sizeof(block_sig));
    memset(leader_set_type, 2, sizeof(leader_set_type));

    // Assign leader sets: half SRRIP, half BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        leader_set_type[i] = 0; // SRRIP
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = 1; // BRRIP
    // The rest remain normal (2)
}

// --- Find victim: standard SRRIP ---
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
    // --- Signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: update SHiP, set RRPV=0 ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = 0;
        return;
    }

    // --- Determine insertion policy ---
    uint8_t ins_rrpv = 2; // default for DRRIP: distant
    bool use_sr = false, use_br = false;

    if (set < NUM_LEADER_SETS) {
        // Leader sets
        if (leader_set_type[set] == 0) {
            // SRRIP: always insert at RRPV=2
            ins_rrpv = 2;
            use_sr = true;
        } else if (leader_set_type[set] == 1) {
            // BRRIP: insert at RRPV=3 with 1/32 probability, else RRPV=2
            if ((rand() % 32) == 0)
                ins_rrpv = 3;
            else
                ins_rrpv = 2;
            use_br = true;
        }
    } else {
        // Normal sets: select based on PSEL
        if (psel >= (PSEL_MAX / 2)) {
            // Use SRRIP
            ins_rrpv = 2;
        } else {
            // Use BRRIP
            if ((rand() % 32) == 0)
                ins_rrpv = 3;
            else
                ins_rrpv = 2;
        }
    }

    // --- SHiP insertion override ---
    // If signature shows high reuse (counter >=2), insert at MRU (RRPV=0)
    // If signature shows dead-on-fill (counter==0), insert at distant (RRPV=3)
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;
    else if (ship_table[sig] == 0)
        ins_rrpv = 3;

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP outcome for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ins_rrpv == 3 && ship_table[victim_sig] > 0)
        ship_table[victim_sig]--; // penalize dead block

    // --- DRRIP set-dueling feedback ---
    // Only leader sets update PSEL
    if (set < NUM_LEADER_SETS) {
        if (use_sr && hit)
            if (psel < PSEL_MAX) psel++;
        if (use_br && hit)
            if (psel > 0) psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + DRRIP Set-Dueling: Final statistics." << std::endl;
    // Optionally print SHiP table histogram, PSEL value
    uint32_t freq_sig = 0, dead_sig = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_table[i] >= 2) freq_sig++;
        if (ship_table[i] == 0) dead_sig++;
    }
    std::cout << "SHiP signatures: " << freq_sig << " high reuse, " << dead_sig << " dead-on-fill." << std::endl;
    std::cout << "DRRIP PSEL: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, SHiP table distribution
}