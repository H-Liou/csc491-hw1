#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata: 6-bit PC signature + 2-bit outcome counter per block ---
uint8_t pc_sig[LLC_SETS][LLC_WAYS];     // 6 bits per block
uint8_t pc_outcome[64];                 // 2 bits per signature; 64-entry table

// --- DIP metadata: 1-bit reuse per block, 2-bit PSEL, 64 leader sets ---
uint8_t reuse_bit[LLC_SETS][LLC_WAYS];  // 1 bit per block
uint16_t PSEL = 512;                    // 2 bits sufficient, but use 10 bits for smooth adaptation
#define DIP_PSEL_MAX 1023
#define DIP_LEADER_SETS 64
bool is_lip_leader[LLC_SETS];
bool is_bip_leader[LLC_SETS];

// --- Parameters ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 64
#define DEAD_BLOCK_THRESHOLD 0 // If reuse_bit==0 on eviction, treat as dead
#define REUSE_DECAY_INTERVAL 4096 // Decay reuse bits every N accesses

uint64_t global_access_counter = 0;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            pc_sig[set][way] = 0;
            reuse_bit[set][way] = 1; // Initially considered potentially useful
        }
        // DIP leader sets: first N LIP, last N BIP
        is_lip_leader[set] = (set < DIP_LEADER_SETS);
        is_bip_leader[set] = (set >= LLC_SETS - DIP_LEADER_SETS);
    }
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        pc_outcome[i] = 1; // neutral (2-bit counter)
    PSEL = DIP_PSEL_MAX / 2;
    global_access_counter = 0;
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // DIP: LRU-style victim selection, but prefer dead blocks
    // First, try to find any block with reuse_bit == 0 (dead block)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (reuse_bit[set][way] == 0)
            return way;
    // Else, evict true LRU (way 0 if no LRU stack, else implement per-block LRU if needed)
    // For simplicity, choose way 0
    return 0;
}

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
    // --- SHiP-lite signature ---
    uint8_t sig = ((PC >> 2) ^ (PC >> 8)) & ((1 << SHIP_SIG_BITS) - 1);

    // --- Dead-block approximation: decay periodically ---
    global_access_counter++;
    if (global_access_counter % REUSE_DECAY_INTERVAL == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s) {
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (reuse_bit[s][w] > 0)
                    reuse_bit[s][w]--;
            }
        }
    }

    if (hit) {
        reuse_bit[set][way] = 1; // Mark as reused
        // Promote PC outcome on hit
        if (pc_outcome[sig] < 3) pc_outcome[sig]++;
    } else {
        // On eviction, demote outcome for victim's signature if dead block
        uint8_t victim_sig = pc_sig[set][way];
        if (reuse_bit[set][way] == DEAD_BLOCK_THRESHOLD) {
            if (pc_outcome[victim_sig] > 0) pc_outcome[victim_sig]--;
        }

        // --- DIP insertion policy selection ---
        bool use_bip = false;
        if (is_bip_leader[set])
            use_bip = true;
        else if (is_lip_leader[set])
            use_bip = false;
        else
            use_bip = (PSEL < (DIP_PSEL_MAX / 2));

        // --- SHiP-lite bias ---
        if (pc_outcome[sig] >= 2) {
            // Hot PC, insert at MRU (reuse_bit=1)
            reuse_bit[set][way] = 1;
        } else {
            // Cold PC, use DIP-selected policy
            if (use_bip) {
                // BIP: insert at LRU (reuse_bit=0) except 1/32 times at MRU
                if ((rand() % 32) == 0)
                    reuse_bit[set][way] = 1;
                else
                    reuse_bit[set][way] = 0;
            } else {
                // LIP: always insert at LRU (reuse_bit=0)
                reuse_bit[set][way] = 0;
            }
        }
        pc_sig[set][way] = sig;

        // --- DIP set-dueling update ---
        if (is_bip_leader[set]) {
            if (hit && reuse_bit[set][way] == 1)
                if (PSEL < DIP_PSEL_MAX) PSEL++;
        }
        if (is_lip_leader[set]) {
            if (hit && reuse_bit[set][way] == 1)
                if (PSEL > 0) PSEL--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_blocks = 0, cold_blocks = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (pc_outcome[i] >= 2) hot_blocks++;
        else cold_blocks++;
    }
    std::cout << "DIP-SHiP-DBD: Hot PC signatures: " << hot_blocks
              << " / " << SHIP_TABLE_SIZE << std::endl;
    std::cout << "DIP-SHiP-DBD: Cold PC signatures: " << cold_blocks << std::endl;
    int dead_blocks = 0, live_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (reuse_bit[set][way] == 0) dead_blocks++;
            else live_blocks++;
    std::cout << "DIP-SHiP-DBD: Dead blocks: " << dead_blocks
              << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "DIP-SHiP-DBD: Live blocks: " << live_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (reuse_bit[set][way] == 0) dead_blocks++;
    std::cout << "DIP-SHiP-DBD: Dead blocks: " << dead_blocks << std::endl;
}