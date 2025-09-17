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

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DRRIP set-dueling: 64 leader sets, 10-bit PSEL ---
#define LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;           // 10-bit selector
bool is_srrip_leader[LLC_SETS];
bool is_brrip_leader[LLC_SETS];

// --- Streaming detector: per-set, last address and stride, 2-bit monotonic counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];
uint8_t monotonic_count[LLC_SETS];

// --- Parameters ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 64
#define BRRIP_INSERT_PROB 1 // Insert at distant RRPV (3) with prob 1/32
#define STREAM_THRESHOLD 3  // Streaming detected if monotonic_count >= 3

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            pc_sig[set][way] = 0;
        }
        last_addr[set] = 0;
        last_stride[set] = 0;
        monotonic_count[set] = 0;
        // Leader sets for DRRIP set-dueling
        is_srrip_leader[set] = (set < LEADER_SETS);
        is_brrip_leader[set] = (set >= LLC_SETS - LEADER_SETS);
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

    // --- Update outcome counter ---
    if (hit) {
        rrpv[set][way] = 0; // promote to MRU
        if (pc_outcome[sig] < 3) pc_outcome[sig]++;
    } else {
        // On eviction, decrement outcome for victim's signature
        uint8_t victim_sig = pc_sig[set][way];
        if (pc_outcome[victim_sig] > 0) pc_outcome[victim_sig]--;
        // Insert new block with signature
        pc_sig[set][way] = sig;

        // --- Streaming bypass logic ---
        bool stream_detected = (monotonic_count[set] >= STREAM_THRESHOLD);
        bool insert_at_lru = false;

        // If streaming detected, always insert at LRU (RRIP=3) to minimize pollution
        if (stream_detected) {
            rrpv[set][way] = 3;
            insert_at_lru = true;
        } else {
            // Else, use DRRIP set-dueling (SRRIP/BRRIP)
            bool use_brrip = false;
            if (is_brrip_leader[set])
                use_brrip = true;
            else if (is_srrip_leader[set])
                use_brrip = false;
            else
                use_brrip = (PSEL < (PSEL_MAX / 2));

            // If SHiP says PC is "hot", insert at MRU; "cold" at LRU
            if (pc_outcome[sig] >= 2) {
                rrpv[set][way] = 0; // hot PC, retain
            } else if (use_brrip) {
                // BRRIP: insert at LRU (3) with low probability, else mid (2)
                if ((rand() % 32) < BRRIP_INSERT_PROB)
                    rrpv[set][way] = 3;
                else
                    rrpv[set][way] = 2;
            } else {
                // SRRIP: insert at mid (2)
                rrpv[set][way] = 2;
            }
        }

        // --- DRRIP set-dueling update ---
        if (is_brrip_leader[set]) {
            if (hit && !insert_at_lru && rrpv[set][way] == 0 && !stream_detected)
                if (PSEL < PSEL_MAX) PSEL++; // BRRIP leader hit
        }
        if (is_srrip_leader[set]) {
            if (hit && !insert_at_lru && rrpv[set][way] == 0 && !stream_detected)
                if (PSEL > 0) PSEL--; // SRRIP leader hit
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
    std::cout << "SHiP-Lite-SB: Hot PC signatures: " << hot_blocks
              << " / " << SHIP_TABLE_SIZE << std::endl;
    std::cout << "SHiP-Lite-SB: Cold PC signatures: " << cold_blocks << std::endl;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-Lite-SB: Streaming sets: " << streaming_sets
              << " / " << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-Lite-SB: Streaming sets: " << streaming_sets << std::endl;
}