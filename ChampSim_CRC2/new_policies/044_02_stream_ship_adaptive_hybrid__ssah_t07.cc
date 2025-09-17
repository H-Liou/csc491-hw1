#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 64
uint8_t block_sig[LLC_SETS][LLC_WAYS];      // Per-block signature
uint8_t ship_ctr[SIG_TABLE_SIZE];           // 2-bit outcome counter per signature

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DIP-style set-dueling for SHiP vs Streaming-aware ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_ship[LLC_SETS];
uint8_t is_leader_stream[LLC_SETS];

// --- Streaming detector: per-set, monitors recent address deltas ---
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];      // 3-bit signed: [-4, +3]
#define STREAM_SCORE_MIN -4
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_THRESH 2       // If score >=2, treat as streaming

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
        }
        is_leader_ship[set] = 0;
        is_leader_stream[set] = 0;
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        ship_ctr[i] = 1;
    // First DUEL_LEADER_SETS sets are SHiP-leader, next DUEL_LEADER_SETS are streaming-leader
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_ship[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_stream[i] = 1;
}

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
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    if (delta == 64 || delta == -64) {
        // Typical cache block streaming stride
        if (stream_score[set] < STREAM_SCORE_MAX)
            stream_score[set]++;
    } else if (delta != 0) {
        if (stream_score[set] > STREAM_SCORE_MIN)
            stream_score[set]--;
    }
    last_addr[set] = paddr;

    // --- Signature extraction ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x3F)) & ((1 << SIG_BITS)-1);
    uint8_t old_sig = block_sig[set][way];

    // --- SHiP-lite update ---
    if (hit) {
        if (ship_ctr[old_sig] < 3)
            ship_ctr[old_sig]++;
        rrpv[set][way] = 0; // MRU
    } else {
        if (ship_ctr[old_sig] > 0)
            ship_ctr[old_sig]--;
        block_sig[set][way] = sig;

        // --- Policy selection: set-dueling ---
        bool use_ship;
        if (is_leader_ship[set])
            use_ship = true;
        else if (is_leader_stream[set])
            use_ship = false;
        else
            use_ship = (psel < (1 << (PSEL_BITS-1)));

        // --- Streaming-aware insertion ---
        bool is_streaming = (stream_score[set] >= STREAM_DETECT_THRESH);
        if (!use_ship && is_streaming) {
            // Streaming detected: insert at distant RRPV, occasionally bypass
            // Bypass with probability 1/8
            if ((PC ^ paddr) & 0x7) {
                rrpv[set][way] = 3; // Bypass
            } else {
                rrpv[set][way] = 2; // Distant
            }
            // Leader set: update PSEL
            if (is_leader_stream[set] && !hit)
                if (psel < ((1<<PSEL_BITS)-1)) psel++;
        }
        // SHiP logic: hot signature gets MRU, else distant
        else if (use_ship && ship_ctr[sig] >= 2) {
            rrpv[set][way] = 0;
            if (is_leader_ship[set] && !hit)
                if (psel > 0) psel--;
        }
        else {
            rrpv[set][way] = 2;
        }
    }
}

void PrintStats() {
    int hot = 0, cold = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (ship_ctr[i] >= 2) hot++;
        else cold++;
    }
    std::cout << "SSAH: Hot PC signatures: " << hot << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SSAH: Cold PC signatures: " << cold << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SSAH: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    int hot = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        if (ship_ctr[i] >= 2) hot++;
    std::cout << "SSAH: Hot signature count: " << hot << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SSAH: Streaming sets: " << stream_sets << std::endl;
}