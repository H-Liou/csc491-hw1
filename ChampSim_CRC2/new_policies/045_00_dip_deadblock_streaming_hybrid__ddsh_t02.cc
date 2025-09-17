#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP-style set-dueling for LIP vs BIP ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_lip[LLC_SETS];
uint8_t is_leader_bip[LLC_SETS];

// --- Dead-block counter: 2 bits per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // [0,3], higher = more likely dead

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, monitors recent address deltas ---
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];      // 3-bit signed: [-4, +3]
#define STREAM_SCORE_MIN -4
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_THRESH 2       // If score >=2, treat as streaming

// --- Periodic decay for dead-block counters ---
uint64_t access_counter = 0;
#define DECAY_PERIOD (LLC_SETS * LLC_WAYS * 8)

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            dead_ctr[set][way] = 0;
        }
        is_leader_lip[set] = 0;
        is_leader_bip[set] = 0;
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    // First DUEL_LEADER_SETS sets are LIP-leader, next DUEL_LEADER_SETS are BIP-leader
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_lip[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_bip[i] = 1;
    psel = (1 << (PSEL_BITS-1));
    access_counter = 0;
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
    access_counter++;
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

    // --- Dead-block counter update ---
    if (hit) {
        if (dead_ctr[set][way] > 0)
            dead_ctr[set][way]--;
        rrpv[set][way] = 0; // MRU on hit
    } else {
        // On eviction, increment dead-block counter
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // --- Periodic decay of dead-block counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }

    // --- Policy selection: set-dueling DIP ---
    bool use_lip;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (psel < (1 << (PSEL_BITS-1)));

    // --- Streaming-aware insertion ---
    bool is_streaming = (stream_score[set] >= STREAM_DETECT_THRESH);

    // --- Insertion depth logic ---
    if (is_streaming) {
        // Streaming detected: insert at distant RRPV, bypass with probability 1/8
        if ((PC ^ paddr) & 0x7) {
            rrpv[set][way] = 3; // Bypass
        } else {
            rrpv[set][way] = 2; // Distant
        }
        // Leader set: update PSEL
        if (is_leader_bip[set] && !hit)
            if (psel < ((1<<PSEL_BITS)-1)) psel++;
    }
    else if (dead_ctr[set][way] == 0) {
        // Block is likely reusable: insert at MRU
        rrpv[set][way] = 0;
        if (is_leader_lip[set] && !hit)
            if (psel > 0) psel--;
    }
    else {
        // DIP logic: LIP (insert at LRU) or BIP (insert at MRU 1/32, else LRU)
        if (use_lip) {
            rrpv[set][way] = 2; // LIP: insert at LRU
        } else {
            if ((PC ^ paddr) & 0x1F)
                rrpv[set][way] = 2; // BIP: insert at LRU
            else
                rrpv[set][way] = 0; // BIP: insert at MRU (1/32)
        }
    }
}

void PrintStats() {
    int dead0 = 0, dead3 = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_ctr[set][way] == 0) dead0++;
            if (dead_ctr[set][way] == 3) dead3++;
        }
    std::cout << "DDSH: Dead-block ctr==0: " << dead0 << " / " << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "DDSH: Dead-block ctr==3: " << dead3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "DDSH: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
    std::cout << "DDSH: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int dead0 = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 0) dead0++;
    std::cout << "DDSH: Dead-block ctr==0: " << dead0 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "DDSH: Streaming sets: " << stream_sets << std::endl;
    std::cout << "DDSH: PSEL: " << psel << std::endl;
}