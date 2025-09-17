#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP set-dueling parameters ---
#define DIP_LEADER_SETS 64
#define DIP_PSEL_MAX 1023
uint16_t DIP_psel = DIP_PSEL_MAX / 2;
uint8_t dip_leader_type[LLC_SETS]; // 0: LRU, 1: BIP

// --- RRPV for SRRIP ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite signature ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6 bits per line
uint8_t ship_table[SHIP_TABLE_SIZE];        // 2 bits per signature

// --- Per-block dead-block counter ---
uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_table, 1, sizeof(ship_table)); // optimistic: assume some reuse
    memset(dead_block, 0, sizeof(dead_block));

    // Assign leader sets: first half LRU, second half BIP
    for (uint32_t i = 0; i < DIP_LEADER_SETS; ++i) {
        dip_leader_type[i] = 0; // LRU
        dip_leader_type[LLC_SETS - i - 1] = 1; // BIP
    }
    for (uint32_t i = DIP_LEADER_SETS; i < LLC_SETS - DIP_LEADER_SETS; ++i)
        dip_leader_type[i] = 2; // Follower
}

// --- SHiP signature hash ---
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & (SHIP_TABLE_SIZE - 1);
}

// --- DIP-style insertion policy ---
inline bool DIP_InsertMRU(uint32_t set) {
    if (dip_leader_type[set] == 0) return true;    // LRU leader
    if (dip_leader_type[set] == 1) return false;   // BIP leader
    // Follower: use PSEL
    return DIP_psel >= DIP_PSEL_MAX / 2;
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
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
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
    uint8_t sig = GetSignature(PC);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        if (ship_table[sig] < 3) ++ship_table[sig];
        if (dead_block[set][way] > 0) --dead_block[set][way];
        return;
    }

    // --- On fill ---
    ship_signature[set][way] = sig;

    // Dead-block: if counter maxed, insert at distant RRPV (bypass)
    if (dead_block[set][way] == 3) {
        rrpv[set][way] = 3;
        return;
    }

    // SHiP advice: dead signature, insert at distant RRPV
    if (ship_table[sig] == 0) {
        rrpv[set][way] = 3;
        return;
    }

    // DIP policy: choose MRU or LRU insertion
    if (DIP_InsertMRU(set)) {
        rrpv[set][way] = 0; // MRU
    } else {
        // BIP: MRU insert 1/32 fills, else LRU
        static thread_local uint32_t bip_ctr = 0;
        if ((bip_ctr++ & 0x1f) == 0)
            rrpv[set][way] = 0;
        else
            rrpv[set][way] = 2;
    }
}

// --- On eviction: update SHiP and dead-block counter ---
void OnEviction(
    uint32_t set, uint32_t way
) {
    uint8_t sig = ship_signature[set][way];
    // If not reused (RRPV==3), mark as dead in SHiP
    if (rrpv[set][way] == 3) {
        if (ship_table[sig] > 0) --ship_table[sig];
        if (dead_block[set][way] < 3) ++dead_block[set][way];
    }
    // If reused, decay dead-block
    else if (dead_block[set][way] > 0) {
        --dead_block[set][way];
    }
}

// --- DIP PSEL adjustment ---
void UpdateDIP_PSEL(
    uint32_t set, uint8_t hit
) {
    // Only for leader sets
    if (dip_leader_type[set] == 0) { // LRU leader
        if (hit && DIP_psel < DIP_PSEL_MAX) ++DIP_psel;
    } else if (dip_leader_type[set] == 1) { // BIP leader
        if (hit && DIP_psel > 0) --DIP_psel;
    }
}

// --- Periodic decay of dead-block counters and SHiP table ---
void DecayMetadata() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_block[set][way] > 0) --dead_block[set][way];
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i] > 0) --ship_table[i];
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DSD Policy: DIP-set-dueling + SHiP-lite + Dead-Block Counters Hybrid\n";
}
void PrintStats_Heartbeat() {}