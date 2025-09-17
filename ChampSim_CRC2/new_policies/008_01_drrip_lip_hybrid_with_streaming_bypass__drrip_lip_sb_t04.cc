#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel;
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: LIP, 3: follower

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector ---
uint64_t last_addr[LLC_SETS];      // last accessed block address per set
int8_t stride_count[LLC_SETS];     // 2-bit signed counter per set
uint8_t streaming_flag[LLC_SETS];  // 1-bit per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stride_count, 0, sizeof(stride_count));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    psel = (1 << (PSEL_BITS - 1));
    // Assign leader sets: evenly distributed
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS / 3) leader_set_type[s] = 0; // SRRIP
        else if (s < 2 * NUM_LEADER_SETS / 3) leader_set_type[s] = 1; // BRRIP
        else if (s < NUM_LEADER_SETS) leader_set_type[s] = 2; // LIP
        else leader_set_type[s] = 3; // follower
    }
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
    // RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

// --- Streaming detector update ---
inline void update_streaming_detector(uint32_t set, uint64_t paddr) {
    uint64_t block_addr = paddr >> 6; // block granularity
    int64_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0) {
        // If delta is +/-1, increment stride_count; else, decrement
        if (delta == 1 || delta == -1)
            stride_count[set] = (stride_count[set] < 3) ? stride_count[set] + 1 : 3;
        else
            stride_count[set] = (stride_count[set] > -2) ? stride_count[set] - 1 : -2;
        // Streaming if stride_count >=2
        streaming_flag[set] = (stride_count[set] >= 2) ? 1 : 0;
    }
    last_addr[set] = block_addr;
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
    update_streaming_detector(set, paddr);

    // On hit: promote block
    if (hit) {
        rrpv[set][way] = 0;
        // DRRIP PSEL update for leader sets
        if (leader_set_type[set] == 0) { // SRRIP leader
            if (psel < ((1 << PSEL_BITS) - 1)) psel++;
        } else if (leader_set_type[set] == 1) { // BRRIP leader
            if (psel > 0) psel--;
        } else if (leader_set_type[set] == 2) { // LIP leader
            // LIP does not update PSEL
        }
        return;
    }

    // Streaming detected: insert at distant RRPV or bypass
    if (streaming_flag[set]) {
        rrpv[set][way] = 3; // Insert at LRU
        return;
    }

    // --- DRRIP set-dueling: choose insertion depth ---
    uint8_t insertion_rrpv = 2; // SRRIP default
    if (leader_set_type[set] == 0) { // SRRIP leader
        insertion_rrpv = 2;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        insertion_rrpv = (rand() % 32 == 0) ? 0 : 2; // MRU with 1/32 probability
    } else if (leader_set_type[set] == 2) { // LIP leader
        insertion_rrpv = 3; // Always insert at LRU
    } else { // follower
        // Choose between SRRIP and BRRIP based on PSEL
        insertion_rrpv = (psel >= (1 << (PSEL_BITS - 1))) ? 2 : ((rand() % 32 == 0) ? 0 : 2);
    }

    rrpv[set][way] = insertion_rrpv;

    // DRRIP PSEL update for leader sets
    if (leader_set_type[set] == 0) { // SRRIP leader
        if (psel < ((1 << PSEL_BITS) - 1)) psel++;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        if (psel > 0) psel--;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) stream_sets++;
    std::cout << "DRRIP-LIP-SB Policy: DRRIP set-dueling + LIP leader + Streaming Bypass" << std::endl;
    std::cout << "Sets with streaming detected: " << stream_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) stream_sets++;
    std::cout << "Streaming sets (heartbeat): " << stream_sets << "/" << LLC_SETS << std::endl;
}