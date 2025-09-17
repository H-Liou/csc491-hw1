#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2 bits RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Dead-block predictor: 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// Streaming detector: 2-bit confidence, 8-bit last_addr, 8-bit last_delta per set
uint8_t stream_conf[LLC_SETS];
uint64_t stream_last_addr[LLC_SETS];
int16_t stream_last_delta[LLC_SETS];

// SRRIP/BRRIP set-dueling: 32 leader sets for SRRIP, 32 for BRRIP
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_srrip[LLC_SETS];
bool is_leader_brrip[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All blocks start distant
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(stream_last_addr, 0, sizeof(stream_last_addr));
    memset(stream_last_delta, 0, sizeof(stream_last_delta));

    // Assign leader sets for SRRIP/BRRIP set-dueling
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_srrip[s] = true, is_leader_brrip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_srrip[s] = false, is_leader_brrip[s] = true;
        else
            is_leader_srrip[s] = false, is_leader_brrip[s] = false;
    }
}

// --- Streaming detector (per-set) ---
inline bool detect_streaming(uint32_t set, uint64_t paddr) {
    int16_t delta = (int16_t)(paddr - stream_last_addr[set]);
    bool monotonic = (delta == stream_last_delta[set]) && (delta != 0);

    if (monotonic) {
        if (stream_conf[set] < 3) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    stream_last_delta[set] = delta;
    stream_last_addr[set] = paddr;

    // Streaming if confidence high
    return (stream_conf[set] >= 2);
}

// --- Find victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // RRIP victim selection: pick block with RRPV==3, else increment all and retry
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
    // --- Streaming detector ---
    bool is_streaming = detect_streaming(set, paddr);

    // --- Dead-block predictor update ---
    if (hit) {
        // On hit, block reused: decrement dead counter, set RRPV to 0
        if (dead_ctr[set][way] > 0) dead_ctr[set][way]--;
        rrpv[set][way] = 0;
        // Periodic decay: every 256 hits, increment all dead counters in set
        static uint32_t hit_count = 0;
        hit_count++;
        if ((hit_count & 0xFF) == 0) {
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[set][w] < 3) dead_ctr[set][w]++;
        }
        return;
    }

    // --- Set-dueling: choose insertion policy ---
    bool use_srrip = false;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_brrip[set])
        use_srrip = false;
    else
        use_srrip = (PSEL >= 512);

    uint8_t ins_rrpv = 2; // default SRRIP (insert at 2)
    if (use_srrip)
        ins_rrpv = 2; // SRRIP: always insert at 2
    else
        ins_rrpv = ((rand() % 32) == 0) ? 2 : 3; // BRRIP: mostly distant, rare 2

    // --- Dead-block: if block predicted dead, insert at distant ---
    if (dead_ctr[set][way] >= 2 && !is_streaming)
        ins_rrpv = 3;

    // --- Streaming: if streaming detected, bypass (do not fill) ---
    if (is_streaming) {
        rrpv[set][way] = 3; // treat as distant (could optionally not fill)
        dead_ctr[set][way] = 2; // mark as likely dead
        return;
    }

    rrpv[set][way] = ins_rrpv;
    // On fill, initialize dead counter to 1 (neutral)
    dead_ctr[set][way] = 1;

    // --- Set-dueling update ---
    if (is_leader_srrip[set] && hit) {
        if (PSEL < 1023) PSEL++;
    } else if (is_leader_brrip[set] && hit) {
        if (PSEL > 0) PSEL--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SRRIP-DeadBlock Hybrid + Streaming Bypass: Final statistics." << std::endl;
    // Optionally print dead counter histogram, streaming confidence, PSEL
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print dead counter histogram, streaming confidence, PSEL
}