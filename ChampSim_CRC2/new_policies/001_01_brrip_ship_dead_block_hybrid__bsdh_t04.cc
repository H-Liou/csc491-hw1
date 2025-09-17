#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2 bits/line: RRPV
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 5 bits/line: PC signature
uint8_t pc_sig[LLC_SETS][LLC_WAYS];

// SHiP table: 2K entries, 2 bits/counter
#define SHIP_TABLE_SIZE 2048
uint8_t ship_table[SHIP_TABLE_SIZE];

// Dead-block: 1 bit/line
uint8_t dead_block[LLC_SETS][LLC_WAYS];

// DRRIP/BRRIP set-dueling
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1));
#define NUM_LEADER_SETS 32
uint8_t is_drrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];

// Helper: hash PC to 5 bits
inline uint8_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 7) ^ (PC >> 13)) & 0x1F;
}

// Helper: hash signature to SHiP table index
inline uint16_t ship_index(uint8_t sig) {
    return sig;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // Initialize to distant
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // Neutral reuse
    memset(dead_block, 0, sizeof(dead_block));

    // Set up leader sets for DRRIP/BRRIP
    memset(is_drrip_leader, 0, sizeof(is_drrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_drrip_leader[i] = 1; // First N sets: DRRIP leaders
        is_brrip_leader[LLC_SETS - 1 - i] = 1; // Last N sets: BRRIP leaders
    }
    PSEL = (1 << (PSEL_BITS - 1));
}

// --- Victim selection: SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks first
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_block[set][way])
            return way;
    }
    // Find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
    }
}

// --- Replacement state update ---
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
    uint8_t sig = get_signature(PC);
    uint16_t idx = ship_index(sig);

    // On hit: promote to MRU, increment SHiP counter, clear dead flag
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_table[idx] < 3)
            ship_table[idx]++;
        dead_block[set][way] = 0;
    } else {
        // On fill: decide insertion depth via DRRIP/BRRIP set-dueling
        bool use_drrip = false;
        if (is_drrip_leader[set])
            use_drrip = true;
        else if (is_brrip_leader[set])
            use_drrip = false;
        else
            use_drrip = (PSEL >= (1 << (PSEL_BITS - 1)));

        uint8_t ship_score = ship_table[idx];
        pc_sig[set][way] = sig;

        // Dead-block: insert at distant
        if (dead_block[set][way]) {
            rrpv[set][way] = 3;
        }
        // SHiP high reuse: insert MRU
        else if (ship_score >= 2) {
            rrpv[set][way] = 0;
        }
        // Otherwise: use DRRIP/BRRIP winner
        else {
            if (use_drrip) {
                // DRRIP: 1/32 BRRIP, otherwise SRRIP
                if ((rand() % 32) == 0)
                    rrpv[set][way] = 2;
                else
                    rrpv[set][way] = 3;
            } else {
                // BRRIP: 1/32 MRU, otherwise distant
                if ((rand() % 32) == 0)
                    rrpv[set][way] = 0;
                else
                    rrpv[set][way] = 2;
            }
        }
        // Mark block as not dead on fill
        dead_block[set][way] = 0;
    }

    // On eviction: decay SHiP counter if not reused; update PSEL for leader sets
    if (!hit) {
        uint8_t evict_sig = pc_sig[set][way];
        uint16_t evict_idx = ship_index(evict_sig);
        if (ship_table[evict_idx] > 0)
            ship_table[evict_idx]--;

        // Dead-block approximation: if block was not reused, set dead flag
        dead_block[set][way] = 1;

        // Update PSEL: DRRIP leader sets increment on hit, BRRIP leader sets decrement on hit
        if (is_drrip_leader[set] && hit && PSEL < ((1 << PSEL_BITS) - 1))
            PSEL++;
        if (is_brrip_leader[set] && hit && PSEL > 0)
            PSEL--;
    }
}

// --- Dead-block periodic decay (call every N million accesses) ---
void DecayDeadBlockFlags() {
    // Clear dead flags periodically to avoid stuck blocks
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            dead_block[s][w] = 0;
}

// --- Stats ---
void PrintStats() {
    std::cout << "BSDH: SHiP table (reuse counters) summary:" << std::endl;
    int reused = 0, total = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_table[i] >= 2) reused++;
        total++;
    }
    std::cout << "High-reuse signatures: " << reused << " / " << total << std::endl;
    // Dead-block stats
    int dead_count = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w]) dead_count++;
    std::cout << "Dead blocks: " << dead_count << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    int dead_count = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w]) dead_count++;
    std::cout << "BSDH: Dead blocks: " << dead_count << std::endl;
    std::cout << "BSDH: PSEL: " << PSEL << std::endl;
}