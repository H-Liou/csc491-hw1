#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// DRRIP: Set-dueling leader sets (64 total)
#define NUM_LEADER_SETS 64
uint8_t is_sr_leader[LLC_SETS];
uint8_t is_br_leader[LLC_SETS];

// DRRIP: 10-bit PSEL selector
uint16_t PSEL = 512; // range: 0..1023, start neutral

// Streaming detector: per-set, last address and delta, 2-bit streaming counter
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));

    // Assign leader sets for SRRIP and BRRIP
    memset(is_sr_leader, 0, sizeof(is_sr_leader));
    memset(is_br_leader, 0, sizeof(is_br_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_sr_leader[i] = 1; // First 32 sets: SRRIP leaders
        is_br_leader[i + NUM_LEADER_SETS] = 1; // Next 32 sets: BRRIP leaders
    }
    PSEL = 512;
}

// Streaming detector (called on every access/fill)
void UpdateStreamingDetector(uint32_t set, uint64_t paddr) {
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        // Monotonic stride detected, saturate counter
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        // Not streaming, decay counter
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
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
    // Standard RRIP victim search
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
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
    // --- Streaming detection ---
    UpdateStreamingDetector(set, paddr);

    // --- On hit: promote to MRU ---
    if (hit) {
        rrpv[set][way] = 0;
        return;
    }

    // --- DRRIP insertion depth selection ---
    uint8_t ins_rrpv = 2; // SRRIP: insert at RRPV=2
    bool use_brrip = false;

    // Leader sets: decide policy and update PSEL
    if (is_sr_leader[set]) {
        ins_rrpv = 2; // SRRIP
        // On miss, if block is not reused, decrement PSEL
        if (rrpv[set][way] == 3)
            if (PSEL > 0) PSEL--;
    } else if (is_br_leader[set]) {
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at 2 with 1/32 prob, else 3
        // On miss, if block is reused, increment PSEL
        if (rrpv[set][way] == 0)
            if (PSEL < 1023) PSEL++;
    } else {
        // Follower sets: use global PSEL to choose
        if (PSEL >= 512) {
            ins_rrpv = 2; // SRRIP
        } else {
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
        }
    }

    // --- Streaming: if streaming detected, force distant RRPV ---
    if (stream_ctr[set] >= 2)
        ins_rrpv = 3;

    rrpv[set][way] = ins_rrpv;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print PSEL value
    std::cout << "DRRIP-SH: Final PSEL value: " << PSEL << std::endl;

    // Streaming counter histogram
    uint64_t stream_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        stream_hist[stream_ctr[s]]++;
    std::cout << "DRRIP-SH: Streaming counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age streaming counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] > 0)
            stream_ctr[s]--;
}