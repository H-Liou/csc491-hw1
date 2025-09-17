#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Dead-block counter: 2 bits per block ---
uint8_t dead_score[LLC_SETS][LLC_WAYS]; // 0 (live) to 3 (very dead)

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DIP-style set-dueling for SRRIP vs BRRIP ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_srrip[LLC_SETS];
uint8_t is_leader_brrip[LLC_SETS];

// --- Streaming detector: per-set, monitors recent address deltas ---
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];      // 3-bit signed: [-4, +3]
#define STREAM_SCORE_MIN -4
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_THRESH 2       // If score >=2, treat as streaming

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // SRRIP default
            dead_score[set][way] = 0;
        }
        is_leader_srrip[set] = 0;
        is_leader_brrip[set] = 0;
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    // First DUEL_LEADER_SETS sets are SRRIP-leader, next DUEL_LEADER_SETS are BRRIP-leader
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_srrip[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_brrip[i] = 1;
    psel = (1 << (PSEL_BITS-1));
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer block with highest dead_score (most likely dead)
    uint32_t victim = LLC_WAYS;
    uint8_t max_dead = 0;
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_score[set][way] == 3) {
            return way;
        }
        if (dead_score[set][way] > max_dead) {
            max_dead = dead_score[set][way];
            victim = way;
        }
    }

    // If no dead block, use standard RRIP victim selection
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

    // --- Dead-block counter update ---
    if (hit) {
        if (dead_score[set][way] > 0)
            dead_score[set][way]--;
        rrpv[set][way] = 0; // MRU on hit
    } else {
        // On replacement, decay dead_score for all blocks in set
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_score[set][w] < 3)
                dead_score[set][w]++;
        }
        dead_score[set][way] = 0; // New block starts live
        // --- Policy selection: set-dueling ---
        bool use_srrip;
        if (is_leader_srrip[set])
            use_srrip = true;
        else if (is_leader_brrip[set])
            use_srrip = false;
        else
            use_srrip = (psel < (1 << (PSEL_BITS-1)));

        // --- Streaming-aware insertion ---
        bool is_streaming = (stream_score[set] >= STREAM_DETECT_THRESH);
        if (is_streaming) {
            // Streaming detected: bypass with probability 1/8, else distant RRPV
            if ((PC ^ paddr) & 0x7) {
                rrpv[set][way] = 3; // Bypass
            } else {
                rrpv[set][way] = 2; // Distant
            }
            // BRRIP leader: update PSEL
            if (is_leader_brrip[set] && !hit)
                if (psel < ((1<<PSEL_BITS)-1)) psel++;
        }
        else if (use_srrip) {
            // SRRIP: insert at RRPV=2 (distant) always
            rrpv[set][way] = 2;
            // SRRIP leader: update PSEL
            if (is_leader_srrip[set] && !hit)
                if (psel > 0) psel--;
        }
        else {
            // BRRIP: insert at RRPV=2 most of the time, but RRPV=3 with prob 1/32
            if ((PC ^ paddr) & 0x1F)
                rrpv[set][way] = 2;
            else
                rrpv[set][way] = 3;
            // BRRIP leader: update PSEL
            if (is_leader_brrip[set] && !hit)
                if (psel < ((1<<PSEL_BITS)-1)) psel++;
        }
    }
}

void PrintStats() {
    int dead_blocks = 0, live_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_score[set][way] == 3)
                dead_blocks++;
            else
                live_blocks++;
        }
    }
    std::cout << "DSSH: Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "DSSH: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_score[set][way] == 3)
                dead_blocks++;
    std::cout << "DSSH: Dead block count: " << dead_blocks << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "DSSH: Streaming sets: " << stream_sets << std::endl;
}