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

// DRRIP set-dueling: 32 leader sets for SRRIP, 32 for BRRIP
#define NUM_LEADER_SETS 32
uint8_t is_leader_srrip[LLC_SETS];
uint8_t is_leader_brrip[LLC_SETS];

// DRRIP PSEL: 10 bits
uint16_t psel = 512; // midpoint

// Per-set streaming detector: last delta (8 bits), streaming count (4 bits)
uint8_t last_delta[LLC_SETS];
uint8_t streaming_score[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // Initialize to distant
    memset(is_leader_srrip, 0, sizeof(is_leader_srrip));
    memset(is_leader_brrip, 0, sizeof(is_leader_brrip));
    memset(last_delta, 0, sizeof(last_delta));
    memset(streaming_score, 0, sizeof(streaming_score));
    psel = 512;

    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_srrip[i] = 1; // first 32 sets: SRRIP leaders
        is_leader_brrip[LLC_SETS - 1 - i] = 1; // last 32 sets: BRRIP leaders
    }
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
    // Standard SRRIP victim selection
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
    // Streaming detector: update delta and score
    uint8_t cur_delta = (uint8_t)((paddr >> 6) - last_delta[set]);
    if (last_delta[set] != 0 && (cur_delta == last_delta[set] || cur_delta == 1 || cur_delta == (uint8_t)-1)) {
        // Monotonic stride detected
        if (streaming_score[set] < 15)
            streaming_score[set]++;
    } else {
        if (streaming_score[set] > 0)
            streaming_score[set]--;
    }
    last_delta[set] = (uint8_t)(paddr >> 6);

    // On hit: promote to MRU
    if (hit) {
        rrpv[set][way] = 0;
        return;
    }

    // On fill: choose insertion depth
    bool streaming = (streaming_score[set] >= 10); // threshold for streaming phase

    uint8_t insert_rrpv = 2; // default distant

    if (streaming) {
        // Streaming detected: insert at most distant (bypass if possible)
        insert_rrpv = 3;
    } else {
        // DRRIP logic
        if (is_leader_srrip[set]) {
            insert_rrpv = 0; // SRRIP: MRU insert
        } else if (is_leader_brrip[set]) {
            insert_rrpv = (rand() % 32 == 0) ? 0 : 2; // BRRIP: 1/32 MRU, else distant
        } else {
            // Follower sets: use PSEL to choose
            if (psel >= 512) {
                insert_rrpv = 0; // SRRIP
            } else {
                insert_rrpv = (rand() % 32 == 0) ? 0 : 2; // BRRIP
            }
        }
    }
    rrpv[set][way] = insert_rrpv;

    // DRRIP set-dueling: update PSEL
    if (is_leader_srrip[set] && !hit) {
        // Miss in SRRIP leader: decrement PSEL
        if (psel > 0) psel--;
    } else if (is_leader_brrip[set] && !hit) {
        // Miss in BRRIP leader: increment PSEL
        if (psel < 1023) psel++;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SDRRIP-SH: PSEL value: " << psel << std::endl;
    // Streaming score summary
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_score[s] >= 10) streaming_sets++;
    std::cout << "Sets in streaming mode: " << streaming_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_score[s] >= 10) streaming_sets++;
    std::cout << "SDRRIP-SH: Streaming sets: " << streaming_sets << std::endl;
}