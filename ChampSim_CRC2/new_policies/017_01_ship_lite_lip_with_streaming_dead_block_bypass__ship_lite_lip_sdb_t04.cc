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

// --- Dead-block counter: 2 bits per block ---
uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- DIP set-dueling: 64 leader sets, 2-bit PSEL ---
#define LEADER_SETS 64
#define PSEL_MAX 3
uint8_t PSEL = PSEL_MAX / 2;            // 2-bit selector
bool is_lip_leader[LLC_SETS];
bool is_bip_leader[LLC_SETS];

// --- Streaming detector: per-set, last address and stride, 2-bit monotonic counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];
uint8_t monotonic_count[LLC_SETS];

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Parameters ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 64
#define BIP_INSERT_PROB 1 // Insert at MRU with prob 1/32
#define STREAM_THRESHOLD 3  // Streaming detected if monotonic_count >= 3

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            pc_sig[set][way] = 0;
            dead_block[set][way] = 0;
        }
        last_addr[set] = 0;
        last_stride[set] = 0;
        monotonic_count[set] = 0;
        // Leader sets for DIP set-dueling
        is_lip_leader[set] = (set < LEADER_SETS);
        is_bip_leader[set] = (set >= LLC_SETS - LEADER_SETS);
    }
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        pc_outcome[i] = 1; // neutral (2-bit counter)
    PSEL = PSEL_MAX / 2;
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
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
    }
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
    // --- Streaming detector update ---
    int64_t stride = (last_addr[set] == 0) ? 0 : int64_t(paddr) - int64_t(last_addr[set]);
    if (last_addr[set] != 0 && stride == last_stride[set] && stride != 0) {
        if (monotonic_count[set] < 3) monotonic_count[set]++;
    } else {
        if (monotonic_count[set] > 0) monotonic_count[set]--;
    }
    last_addr[set] = paddr;
    last_stride[set] = stride;

    // --- SHiP-lite signature ---
    uint8_t sig = ((PC >> 2) ^ (PC >> 8)) & ((1 << SHIP_SIG_BITS) - 1);

    // --- Dead-block counter update ---
    if (hit) {
        rrpv[set][way] = 0; // promote to MRU
        dead_block[set][way] = 0; // reset dead-block counter on reuse
        if (pc_outcome[sig] < 3) pc_outcome[sig]++;
    } else {
        // On eviction, update dead-block counter for victim's signature
        uint8_t victim_sig = pc_sig[set][way];
        if (dead_block[set][way] < 3) dead_block[set][way]++;
        // If block was not reused (dead), penalize PC outcome
        if (dead_block[set][way] == 3 && pc_outcome[victim_sig] > 0) pc_outcome[victim_sig]--;

        // Insert new block with signature
        pc_sig[set][way] = sig;
        dead_block[set][way] = 0; // reset for new block

        // --- Streaming bypass logic ---
        bool stream_detected = (monotonic_count[set] >= STREAM_THRESHOLD);
        bool bypass_block = false;

        // If streaming detected, bypass unless PC is hot or dead-block counter is low
        if (stream_detected && pc_outcome[sig] < 2) {
            // Bypass insertion for cold PC signatures during streaming
            bypass_block = true;
        }

        if (bypass_block) {
            // Mark block as invalid (simulate bypass: set RRPV to max so it's replaced immediately)
            rrpv[set][way] = 3;
        } else {
            // DIP set-dueling: choose between LIP and BIP
            bool use_bip = false;
            if (is_bip_leader[set])
                use_bip = true;
            else if (is_lip_leader[set])
                use_bip = false;
            else
                use_bip = (PSEL < (PSEL_MAX / 2));

            if (use_bip) {
                // BIP: insert at MRU (0) with low probability, else at LRU (3)
                if ((rand() % 32) < BIP_INSERT_PROB)
                    rrpv[set][way] = 0;
                else
                    rrpv[set][way] = 3;
            } else {
                // LIP: always insert at LRU (3)
                rrpv[set][way] = 3;
            }
            // If SHiP says PC is "hot", insert at MRU
            if (pc_outcome[sig] >= 2)
                rrpv[set][way] = 0;
        }

        // --- DIP set-dueling update ---
        if (is_bip_leader[set]) {
            if (hit && !bypass_block && rrpv[set][way] == 0 && !stream_detected)
                if (PSEL < PSEL_MAX) PSEL++; // BIP leader hit
        }
        if (is_lip_leader[set]) {
            if (hit && !bypass_block && rrpv[set][way] == 0 && !stream_detected)
                if (PSEL > 0) PSEL--; // LIP leader hit
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
    std::cout << "SHiP-Lite-LIP-SDB: Hot PC signatures: " << hot_blocks
              << " / " << SHIP_TABLE_SIZE << std::endl;
    std::cout << "SHiP-Lite-LIP-SDB: Cold PC signatures: " << cold_blocks << std::endl;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-Lite-LIP-SDB: Streaming sets: " << streaming_sets
              << " / " << LLC_SETS << std::endl;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_block[set][way] == 3) dead_blocks++;
    std::cout << "SHiP-Lite-LIP-SDB: Dead blocks: " << dead_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-Lite-LIP-SDB: Streaming sets: " << streaming_sets << std::endl;
}