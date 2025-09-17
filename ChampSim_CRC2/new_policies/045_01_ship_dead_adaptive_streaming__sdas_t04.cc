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

// --- DIP-style set-dueling for SHiP vs Dead/Streaming-aware ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_ship[LLC_SETS];
uint8_t is_leader_ds[LLC_SETS];

// --- Streaming detector: per-set stride score ---
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];      // 3-bit signed: [-4, +3]
#define STREAM_SCORE_MIN -4
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_THRESH 2       // If score >=2, treat as streaming

// --- Dead-block counter: per-block, 2-bit, decays every 4096 accesses ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];
uint64_t global_access_counter = 0;

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            dead_ctr[set][way] = 1;
        }
        is_leader_ship[set] = 0;
        is_leader_ds[set] = 0;
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        ship_ctr[i] = 1;
    // First DUEL_LEADER_SETS sets are SHiP-leader, next DUEL_LEADER_SETS are DS-leader
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_ship[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_ds[i] = 1;
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
    global_access_counter++;

    // --- Streaming detector update ---
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    if (delta == 64 || delta == -64) {
        if (stream_score[set] < STREAM_SCORE_MAX)
            stream_score[set]++;
    } else if (delta != 0) {
        if (stream_score[set] > STREAM_SCORE_MIN)
            stream_score[set]--;
    }
    last_addr[set] = paddr;

    // --- Dead-block counter decay: every 4096 accesses, decay all counters by 1 ---
    if ((global_access_counter & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }

    // --- Signature extraction ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x3F)) & ((1 << SIG_BITS)-1);
    uint8_t old_sig = block_sig[set][way];

    // --- SHiP-lite update ---
    if (hit) {
        if (ship_ctr[old_sig] < 3)
            ship_ctr[old_sig]++;
        rrpv[set][way] = 0; // MRU
        dead_ctr[set][way] = 2; // Mark as live
    } else {
        if (ship_ctr[old_sig] > 0)
            ship_ctr[old_sig]--;
        block_sig[set][way] = sig;

        // --- Policy selection: set-dueling ---
        bool use_ship;
        if (is_leader_ship[set])
            use_ship = true;
        else if (is_leader_ds[set])
            use_ship = false;
        else
            use_ship = (psel < (1 << (PSEL_BITS-1)));

        // --- Streaming-aware & dead-block-aware insertion ---
        bool is_streaming = (stream_score[set] >= STREAM_DETECT_THRESH);
        bool is_dead = (dead_ctr[set][way] == 0);

        if (!use_ship && (is_streaming || is_dead)) {
            // Streaming or dead block: insert at distant RRPV, bypass with probability 1/8
            if ((PC ^ paddr) & 0x7) {
                rrpv[set][way] = 3; // Bypass
            } else {
                rrpv[set][way] = 2; // Distant
            }
            // DS leader: update PSEL
            if (is_leader_ds[set] && !hit)
                if (psel < ((1<<PSEL_BITS)-1)) psel++;
        }
        // SHiP logic: hot signature gets MRU, else distant
        else if (use_ship && ship_ctr[sig] >= 2) {
            rrpv[set][way] = 0;
            dead_ctr[set][way] = 2;
            if (is_leader_ship[set] && !hit)
                if (psel > 0) psel--;
        }
        else {
            rrpv[set][way] = 2;
            dead_ctr[set][way] = 1;
        }
    }
}

void PrintStats() {
    int hot = 0, cold = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (ship_ctr[i] >= 2) hot++;
        else cold++;
    }
    std::cout << "SDAS: Hot PC signatures: " << hot << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SDAS: Cold PC signatures: " << cold << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SDAS: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 0)
                dead_blocks++;
    std::cout << "SDAS: Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
}

void PrintStats_Heartbeat() {
    int hot = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        if (ship_ctr[i] >= 2) hot++;
    std::cout << "SDAS: Hot signature count: " << hot << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SDAS: Streaming sets: " << stream_sets << std::endl;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 0)
                dead_blocks++;
    std::cout << "SDAS: Dead blocks: " << dead_blocks << std::endl;
}