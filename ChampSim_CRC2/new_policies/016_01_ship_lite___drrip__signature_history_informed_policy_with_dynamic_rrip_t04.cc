#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP Set-Dueling Metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line
static uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower
static uint16_t PSEL = 512; // 10-bit saturating counter

// --- SHiP-lite Metadata ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS) // 64 entries
static uint8_t ship_counter[SHIP_TABLE_SIZE]; // 2 bits per entry
static uint8_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_counter, 1, sizeof(ship_counter)); // Start neutral
    memset(line_sig, 0, sizeof(line_sig));
    memset(leader_set_type, 2, sizeof(leader_set_type)); // Default: follower

    // Assign leader sets (32 SRRIP, 32 BRRIP)
    for (uint32_t i = 0; i < LLC_SETS; ++i) {
        if (i % 64 == 0) leader_set_type[i] = 0; // SRRIP leader
        else if (i % 64 == 1) leader_set_type[i] = 1; // BRRIP leader
    }
}

// --- Find victim: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment RRPVs (aging)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
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
    // --- SHiP signature ---
    uint8_t sig = (uint8_t)(champsim_crc2(PC, 0) & (SHIP_TABLE_SIZE - 1));

    // On hit: promote and update SHiP counter
    if (hit) {
        rrpv[set][way] = 0; // MRU
        if (ship_counter[sig] < 3) ship_counter[sig]++;
        return;
    }

    // On miss: determine insertion policy
    uint8_t ins_rrpv = 2; // default SRRIP insertion

    // Leader set type
    uint8_t ltype = leader_set_type[set];
    if (ltype == 0) { // SRRIP leader
        ins_rrpv = 2;
    } else if (ltype == 1) { // BRRIP leader
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: 1/32 at 2, rest at 3
    } else { // Follower
        ins_rrpv = (PSEL >= 512) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
    }

    // SHiP counter bias: if signature shows reuse, insert more aggressively
    if (ship_counter[sig] >= 2) ins_rrpv = 0; // insert at MRU

    rrpv[set][way] = ins_rrpv;
    line_sig[set][way] = sig;

    // On eviction, update SHiP counter
    uint8_t victim_sig = line_sig[set][way];
    if (!hit) {
        if (ship_counter[victim_sig] > 0) ship_counter[victim_sig]--;
    }

    // Update PSEL for leader sets
    if (ltype == 0) { // SRRIP leader
        if (hit && PSEL < 1023) PSEL++;
    } else if (ltype == 1) { // BRRIP leader
        if (hit && PSEL > 0) PSEL--;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SHiP-Lite + DRRIP Policy\n";
    std::cout << "PSEL value: " << PSEL << " (SRRIP>BRRIP if >=512)\n";
    uint32_t reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_counter[i] >= 2) ++reuse_sigs;
    std::cout << "Signatures with reuse bias: " << reuse_sigs << " / " << SHIP_TABLE_SIZE << std::endl;
}

// --- Heartbeat stats ---
void PrintStats_Heartbeat() {
    // Optional: print periodic PSEL and SHiP reuse count
}