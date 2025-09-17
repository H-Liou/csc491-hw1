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

// DRRIP: 10-bit PSEL selector, 64 leader sets
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // start neutral
#define NUM_LEADER_SETS 64
uint8_t leader_set_type[LLC_SETS]; // 0:SRRIP, 1:BRRIP, else follower

// Streaming detector: per-set, last address and delta, 2-bit streaming counter
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// Helper: assign leader sets for SRRIP and BRRIP
void AssignLeaderSets() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        leader_set_type[s] = 2; // follower
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        leader_set_type[i] = 0; // SRRIP leader
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = 1; // BRRIP leader
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    AssignLeaderSets();
    PSEL = (1 << (PSEL_BITS - 1));
}

// Streaming detector (called on every access/fill)
void UpdateStreamingDetector(uint32_t set, uint64_t paddr) {
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
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
    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Standard RRIP victim search
    while (true) {
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

    // --- On miss/fill: decide insertion depth ---
    uint8_t ins_rrpv = 2; // default SRRIP insertion

    // Streaming: if streaming detected, bypass or insert at distant RRPV
    if (stream_ctr[set] >= 2) {
        // Bypass: do not insert (simulate by setting RRPV=3, so will be evicted soon)
        ins_rrpv = 3;
    } else {
        // DRRIP set-dueling
        if (leader_set_type[set] == 0) { // SRRIP leader
            ins_rrpv = 2;
        } else if (leader_set_type[set] == 1) { // BRRIP leader
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: 1/32 chance of SRRIP, else distant
        } else {
            // Follower: use PSEL to choose
            if (PSEL >= (1 << (PSEL_BITS - 1)))
                ins_rrpv = 2; // SRRIP
            else
                ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
        }
    }

    rrpv[set][way] = ins_rrpv;

    // --- DRRIP PSEL update ---
    if (leader_set_type[set] == 0) { // SRRIP leader
        if (hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        if (hit && PSEL > 0) PSEL--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming counter histogram
    uint64_t stream_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        stream_hist[stream_ctr[s]]++;
    std::cout << "DRRIP-SAB: Streaming counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << stream_hist[i] << " ";
    std::cout << std::endl;

    // PSEL value
    std::cout << "DRRIP-SAB: Final PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age streaming counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] > 0)
            stream_ctr[s]--;
}