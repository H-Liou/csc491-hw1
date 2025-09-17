#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector metadata ---
uint64_t last_addr[LLC_SETS];           // Last accessed address per set
int64_t last_delta[LLC_SETS];           // Last address delta per set
uint8_t stream_ctr[LLC_SETS];           // 2-bit streaming counter per set

// --- Set-dueling for SRRIP vs Streaming ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_srrip[LLC_SETS];      // 1 if SRRIP leader
uint8_t is_leader_stream[LLC_SETS];     // 1 if Streaming leader

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way] = 2;
        last_addr[set] = 0;
        last_delta[set] = 0;
        stream_ctr[set] = 0;
        is_leader_srrip[set] = 0;
        is_leader_stream[set] = 0;
    }
    // First DUEL_LEADER_SETS sets are SRRIP-leader, next DUEL_LEADER_SETS are Streaming-leader
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_srrip[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_stream[i] = 1;
    psel = (1 << (PSEL_BITS-1));
}

// Standard RRIP victim selection
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
    }
}

// Update streaming detector per set
void UpdateStreamingDetector(uint32_t set, uint64_t paddr) {
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    if (last_addr[set] != 0) {
        if (delta == last_delta[set] && delta != 0) {
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
}

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
    // Update streaming detector
    UpdateStreamingDetector(set, paddr);

    // --- Policy selection ---
    bool use_srrip;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_stream[set])
        use_srrip = false;
    else
        use_srrip = (psel < (1 << (PSEL_BITS-1)));

    // --- Insertion depth control ---
    if (hit) {
        rrpv[set][way] = 0; // MRU on hit
    } else {
        // Streaming detected: insert at distant RRPV or bypass
        if (!use_srrip && stream_ctr[set] >= 2) {
            rrpv[set][way] = 3; // Bypass
            // Update PSEL for Streaming leader sets
            if (is_leader_stream[set])
                if (psel < ((1<<PSEL_BITS)-1)) psel++;
        }
        // Otherwise: SRRIP MRU insertion
        else {
            rrpv[set][way] = 0;
            // Update PSEL for SRRIP leader sets
            if (is_leader_srrip[set])
                if (psel > 0) psel--;
        }
    }
}

void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_ctr[set] >= 2) streaming_sets++;
    std::cout << "SRRIP-SD: Streaming sets (ctr>=2): " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "SRRIP-SD: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_ctr[set] >= 2) streaming_sets++;
    std::cout << "SRRIP-SD: Streaming sets: " << streaming_sets << std::endl;
    std::cout << "SRRIP-SD: PSEL: " << psel << std::endl;
}