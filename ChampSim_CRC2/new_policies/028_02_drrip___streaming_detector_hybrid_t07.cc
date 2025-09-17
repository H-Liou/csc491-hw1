#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// DRRIP Set-dueling: 10-bit PSEL
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;

// Leader sets for SRRIP/BRRIP
#define NUM_LEADER_SETS 64
uint8_t leader_type[LLC_SETS]; // 0: normal, 1: SRRIP leader, 2: BRRIP leader

// Streaming detector: Per-set, 2-bit saturating counter, last address
uint64_t last_addr[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// Streaming threshold: consider streaming if counter == 3
#define STREAM_THRESHOLD 3

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    PSEL = PSEL_MAX / 2;
    memset(leader_type, 0, sizeof(leader_type));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));

    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_type[i] = 1; // SRRIP leader
        leader_type[LLC_SETS - 1 - i] = 2; // BRRIP leader
    }
}

// --- Streaming detector update ---
inline void update_streaming(uint32_t set, uint64_t paddr) {
    uint64_t last = last_addr[set];
    uint64_t delta = (last == 0) ? 0 : (paddr > last ? paddr - last : last - paddr);
    // Detect monotonic stride: delta == block size (64B), or small stride
    if (last != 0 && (delta == 64 || delta == 128)) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_addr[set] = paddr;
}

// --- Find victim: RRIP ---
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
    // Update streaming detector
    update_streaming(set, paddr);

    // DRRIP: Choose insertion policy (SRRIP or BRRIP)
    uint8_t ins_rrpv = 2; // default SRRIP: insert at RRPV=2
    bool use_brrip = false;

    if (leader_type[set] == 1) { // SRRIP leader
        ins_rrpv = 2;
    } else if (leader_type[set] == 2) { // BRRIP leader
        // BRRIP: insert mostly at distant (RRPV=3), rarely at 2
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // long re-reference interval
    } else {
        // Normal set: use PSEL to pick
        if (PSEL >= (PSEL_MAX / 2)) {
            ins_rrpv = 2; // SRRIP
        } else {
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
        }
    }

    // Streaming detector: if streaming detected, force distant insertion
    if (stream_ctr[set] >= STREAM_THRESHOLD) {
        ins_rrpv = 3; // streaming, likely dead-on-arrival
    }

    if (hit) {
        rrpv[set][way] = 0; // promote on hit
    } else {
        rrpv[set][way] = ins_rrpv;
    }

    // DRRIP set-dueling: update PSEL
    if (!hit) {
        if (leader_type[set] == 1 && ins_rrpv == 0) { // SRRIP leader, hit on early insert
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (leader_type[set] == 2 && ins_rrpv == 0) { // BRRIP leader, hit on early insert
            if (PSEL > 0) PSEL--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Streaming Detector Hybrid: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= STREAM_THRESHOLD)
            streaming_sets++;
    std::cout << "Sets with streaming detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL final value: " << PSEL << "/" << PSEL_MAX << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and PSEL
}