#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];    // 2-bit RRIP per block

// --- DBP (dead-block prediction): 2-bit per block ---
uint8_t dbp_ctr[LLC_SETS][LLC_WAYS]; // 2-bit saturating, per block

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome per signature ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 2048
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // [0,63]
uint8_t sig_ctr[SIG_TABLE_SIZE];       // 2-bit per signature

// --- Streaming detector: per-set, tracks monotonic deltas ---
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];         // 3-bit signed [-4,+3]
#define STREAM_SCORE_MIN -4
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_THRESH 2

// --- For periodic decay (DBP counters and SHIP outcome counters) ---
uint64_t access_counter = 0;
#define DECAY_PERIOD (SIG_TABLE_SIZE * 8)

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            dbp_ctr[set][way] = 1;
            block_sig[set][way] = 0;
        }
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_ctr[i] = 1; // neutral
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
    // Prefer blocks predicted dead by dbp_ctr (counter == 0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dbp_ctr[set][way] == 0)
            return way;
    // Otherwise, standard RRIP victim selection
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

    bool is_streaming = (stream_score[set] >= STREAM_DETECT_THRESH);

    // --- SHiP signature extraction ---
    uint32_t sig = (PC ^ (paddr>>6)) & ((1<<SIG_BITS)-1);

    // --- DBP update: increment on hit, decay periodically ---
    if (hit) {
        if (dbp_ctr[set][way] < 3)
            dbp_ctr[set][way]++;
    } else {
        // On eviction, decrement DBP (min 0)
        if (dbp_ctr[set][way] > 0)
            dbp_ctr[set][way]--;
    }

    // --- SHiP update ---
    if (hit) {
        if (sig_ctr[sig] < 3)
            sig_ctr[sig]++;
    } else {
        uint32_t victim_sig = block_sig[set][way];
        if (sig_ctr[victim_sig] > 0)
            sig_ctr[victim_sig]--;
    }

    // --- Periodic decay of DBP and SHiP counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
            if (sig_ctr[i] > 0)
                sig_ctr[i]--;
        for (uint32_t set2 = 0; set2 < LLC_SETS; ++set2)
            for (uint32_t way2 = 0; way2 < LLC_WAYS; ++way2)
                if (dbp_ctr[set2][way2] > 0)
                    dbp_ctr[set2][way2]--;
    }

    // --- Insertion policy ---
    bool strong_sig = (sig_ctr[sig] >= 2);
    bool block_dead = (dbp_ctr[set][way] == 0);

    if (is_streaming) {
        // Streaming set: insert at RRPV=3 (bypass with probability 1/2)
        if (((PC ^ paddr) & 0x1) && !hit) {
            rrpv[set][way] = 3;
        } else {
            rrpv[set][way] = 2;
        }
    }
    else if (block_dead && !hit) {
        // Direct dead-block prediction: insert at RRPV=3
        rrpv[set][way] = 3;
    }
    else if (strong_sig) {
        // SHiP bias: reusable block, insert at MRU
        rrpv[set][way] = 0;
    }
    else {
        // Default: insert at distant (RRPV=2)
        rrpv[set][way] = 2;
    }

    // --- Update block's signature ---
    block_sig[set][way] = sig;
}

void PrintStats() {
    int sig2 = 0, sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_ctr[i] == 2) sig2++;
        if (sig_ctr[i] == 3) sig3++;
    }
    std::cout << "DBSAS: sig_ctr==2: " << sig2 << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "DBSAS: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "DBSAS: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
    // Print DBP distribution
    int dbp_dead = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dbp_ctr[set][way] == 0)
                dbp_dead++;
    std::cout << "DBSAS: blocks predicted dead: " << dbp_dead << std::endl;
}

void PrintStats_Heartbeat() {
    int sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_ctr[i] == 3) sig3++;
    std::cout << "DBSAS: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "DBSAS: Streaming sets: " << stream_sets << std::endl;
    int dbp_dead = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dbp_ctr[set][way] == 0)
                dbp_dead++;
    std::cout << "DBSAS: blocks predicted dead: " << dbp_dead << std::endl;
}