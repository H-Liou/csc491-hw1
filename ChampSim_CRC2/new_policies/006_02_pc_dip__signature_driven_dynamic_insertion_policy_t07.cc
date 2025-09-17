#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata ---
#define SIG_BITS 6
#define REUSE_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS];      // 2-bit per block

uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- DIP set-dueling ---
#define DIP_LEADER_SETS 64
#define DIP_LEADER_LRU 0
#define DIP_LEADER_BIP 1
uint8_t dip_leader_type[LLC_SETS]; // 0: not leader, 1: LRU, 2: BIP

// --- DIP global selector ---
#define PSEL_BITS 10
uint16_t psel;

// --- Periodic decay ---
uint64_t access_counter = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(reuse_ctr, 1, sizeof(reuse_ctr)); // Weak reuse
    memset(dip_leader_type, 0, sizeof(dip_leader_type));
    psel = (1 << (PSEL_BITS - 1));
    // Randomly assign leader sets for LRU and BIP
    for (int i = 0; i < DIP_LEADER_SETS; ++i) {
        dip_leader_type[i] = DIP_LEADER_LRU;
        dip_leader_type[i + DIP_LEADER_SETS] = DIP_LEADER_BIP;
    }
}

// --- Simple PC signature hash ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 6)) & ((1 << SIG_BITS) - 1));
}

// --- Victim selection (SRRIP style) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // SRRIP victim search
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

// --- Periodic decay for reuse counters ---
inline void reuse_decay() {
    if ((access_counter & 0xFFF) == 0) { // every 4096 LLC accesses
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (reuse_ctr[set][way] > 0)
                    reuse_ctr[set][way]--;
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
    if ((access_counter & 0xFFF) == 0) reuse_decay();

    uint8_t sig = get_signature(PC);

    // On hit: promote block, increment reuse counter
    if (hit) {
        rrpv[set][way] = 0;
        if (reuse_ctr[set][way] < 3) reuse_ctr[set][way]++;
        // Update PSEL for DIP set-dueling
        if (dip_leader_type[set] == DIP_LEADER_LRU)
            if (psel < ((1 << PSEL_BITS) - 1)) psel++;
        if (dip_leader_type[set] == DIP_LEADER_BIP)
            if (psel > 0) psel--;
        return;
    }

    // Update signature/reuse counter for new fill
    ship_signature[set][way] = sig;
    reuse_ctr[set][way] = 1; // modest confidence

    // DIP leader set logic
    if (dip_leader_type[set] == DIP_LEADER_LRU) {
        rrpv[set][way] = 3; // Always LRU
        return;
    }
    if (dip_leader_type[set] == DIP_LEADER_BIP) {
        // BIP: insert at MRU with small probability, else LRU
        if ((access_counter & 0x1F) == 0) // 1/32 probability
            rrpv[set][way] = 0;
        else
            rrpv[set][way] = 3;
        return;
    }

    // Normal sets: PC-driven reuse or DIP mode
    // If strong reuse (reuse_ctr >=2), insert at MRU
    if (reuse_ctr[set][way] >= 2) {
        rrpv[set][way] = 0; // MRU for strong reuse
    } else {
        // Else DIP: use BIP if psel < mid, else LRU
        if (psel < (1 << (PSEL_BITS-1))) {
            if ((access_counter & 0x1F) == 0)
                rrpv[set][way] = 0;
            else
                rrpv[set][way] = 3;
        } else {
            rrpv[set][way] = 3;
        }
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0, bip_sets=0, lru_sets=0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (dip_leader_type[s] == DIP_LEADER_BIP) bip_sets++;
        if (dip_leader_type[s] == DIP_LEADER_LRU) lru_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (reuse_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "PC-DIP Policy: Signature-driven Dynamic Insertion Policy" << std::endl;
    std::cout << "Leader BIP sets: " << bip_sets << ", Leader LRU sets: " << lru_sets << std::endl;
    std::cout << "Blocks with strong reuse (reuse_ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Final PSEL: " << psel << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (reuse_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
}