#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite Metadata ---
#define SIG_BITS 6
#define SHIP_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- DIP Leader Sets ---
#define NUM_LEADER_SETS 64
uint8_t is_lip_leader[LLC_SETS]; // 1 if LIP leader, 2 if BIP leader, 0 otherwise
uint16_t psel; // 10 bits

// --- Periodic decay ---
uint64_t access_counter = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start at weak reuse
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    psel = (1 << 9); // Midpoint for 10-bit PSEL

    // Assign leader sets: interleave LIP/BIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set_lip = i * (LLC_SETS / NUM_LEADER_SETS);
        uint32_t set_bip = set_lip + (LLC_SETS / (NUM_LEADER_SETS * 2));
        if (set_lip < LLC_SETS) is_lip_leader[set_lip] = 1;
        if (set_bip < LLC_SETS) is_lip_leader[set_bip] = 2;
    }
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>(PC ^ (PC >> 6)) & ((1 << SIG_BITS) - 1);
}

// --- Victim selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

// --- SHiP counter decay (periodic) ---
inline void ship_decay() {
    if ((access_counter & 0xFFF) == 0) { // every 4096 LLC accesses
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (ship_ctr[set][way] > 0)
                    ship_ctr[set][way]--;
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
    access_counter++;
    if ((access_counter & 0xFFF) == 0) ship_decay();

    uint8_t sig = get_signature(PC);

    // On hit: promote block, increment reuse counter
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        return;
    }

    // --- Dead-block bypass in leader sets ---
    if (is_lip_leader[set] || is_lip_leader[set] == 2) {
        if (ship_ctr[set][way] == 0) {
            // Bypass: do not allocate (simulate by setting high RRPV, no update to signature/counter)
            rrpv[set][way] = 3;
            return;
        }
    }

    // --- DIP insertion depth selection ---
    bool use_lip = false;
    if (is_lip_leader[set] == 1) use_lip = true;
    else if (is_lip_leader[set] == 2) use_lip = false;
    else use_lip = (psel < (1 << 9)); // 512 threshold for 10-bit PSEL

    // --- SHIP-based insertion ---
    if (ship_ctr[set][way] >= 2) {
        rrpv[set][way] = 0; // MRU for strong reuse
    } else {
        // DIP insertion depth
        if (use_lip) {
            rrpv[set][way] = 3; // LIP: always LRU
        } else {
            // BIP: insert at LRU except 1/32 at MRU
            if ((access_counter & 0x1F) == 0)
                rrpv[set][way] = 0;
            else
                rrpv[set][way] = 3;
        }
    }
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // modest confidence on new insert

    // --- PSEL update for leader sets ---
    if (is_lip_leader[set] == 1) {
        // LIP leader set: increment PSEL on hit, decrement on miss
        if (hit && psel < 1023) psel++;
        else if (!hit && psel > 0) psel--;
    }
    if (is_lip_leader[set] == 2) {
        // BIP leader set: decrement PSEL on hit, increment on miss
        if (hit && psel > 0) psel--;
        else if (!hit && psel < 1023) psel++;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int lip_leader = 0, bip_leader = 0, strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (is_lip_leader[s] == 1) lip_leader++;
        if (is_lip_leader[s] == 2) bip_leader++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "DSHIP-LDB Policy: DIP-SHiP Hybrid + Leader Set Dead-Block Bypass" << std::endl;
    std::cout << "LIP leader sets: " << lip_leader << ", BIP leader sets: " << bip_leader << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
}