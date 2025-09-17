#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- DRRIP set-dueling: 64 leader sets, 10-bit PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t psel = PSEL_MAX / 2; // 10-bit PSEL
uint8_t is_leader_set[LLC_SETS]; // 0: normal, 1: SRRIP leader, 2: BRRIP leader

// --- Streaming detector: 4 bits per set, tracks monotonic deltas ---
uint8_t stream_score[LLC_SETS]; // 4 bits per set
uint64_t last_addr[LLC_SETS];   // last address per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(stream_score, 0, sizeof(stream_score));
    memset(last_addr, 0, sizeof(last_addr));
    psel = PSEL_MAX / 2;

    // Assign leader sets: first half SRRIP, second half BRRIP
    memset(is_leader_set, 0, sizeof(is_leader_set));
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        is_leader_set[i] = 1; // SRRIP leader
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        is_leader_set[i] = 2; // BRRIP leader
}

// --- Find victim: standard RRIP ---
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
                rrpv[set][way]++;
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
    // --- Streaming detector update ---
    uint64_t delta = (last_addr[set] > 0) ? (paddr > last_addr[set] ? paddr - last_addr[set] : last_addr[set] - paddr) : 0;
    if (last_addr[set] > 0 && delta < 256 && delta > 0) {
        // Small, monotonic stride: streaming
        if (stream_score[set] < 15) stream_score[set]++;
    } else if (last_addr[set] > 0) {
        // Non-monotonic: penalize
        if (stream_score[set] > 0) stream_score[set]--;
    }
    last_addr[set] = paddr;

    // --- DRRIP insertion depth selection ---
    bool streaming = (stream_score[set] >= 12); // threshold for streaming detection

    uint8_t ins_rrpv = 2; // default SRRIP insertion
    if (is_leader_set[set] == 1) {
        // SRRIP leader: always ins_rrpv = 2
        ins_rrpv = 2;
    } else if (is_leader_set[set] == 2) {
        // BRRIP leader: ins_rrpv = 3 with 1/32 probability
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3;
    } else {
        // Follower sets: use PSEL
        if (psel >= (PSEL_MAX / 2))
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
    }

    // --- Streaming bypass/insertion policy ---
    if (streaming) {
        // For streaming sets, bypass insertion (do not update block, treat as distant)
        rrpv[set][way] = 3;
    } else {
        // On hit: promote block
        if (hit)
            rrpv[set][way] = 0;
        else
            rrpv[set][way] = ins_rrpv;
    }

    // --- DRRIP set-dueling update ---
    if (!hit) {
        if (is_leader_set[set] == 1 && ins_rrpv == 2) {
            // SRRIP leader miss: penalize PSEL
            if (psel > 0) psel--;
        } else if (is_leader_set[set] == 2 && ins_rrpv != 2) {
            // BRRIP leader miss: reward PSEL
            if (psel < PSEL_MAX) psel++;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Streaming Detector Hybrid: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 12)
            streaming_sets++;
    std::cout << "Sets detected as streaming: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Final PSEL value: " << psel << "/" << PSEL_MAX << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and PSEL histogram
}