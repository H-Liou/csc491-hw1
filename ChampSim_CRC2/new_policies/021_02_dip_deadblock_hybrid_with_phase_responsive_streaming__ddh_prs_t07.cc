#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- DIP Set-dueling Metadata ----
#define NUM_LEADER_SETS 64
uint8_t is_lip_leader[LLC_SETS];
uint8_t is_bip_leader[LLC_SETS];
uint16_t psel; // 10 bits

// ---- Dead-block Predictor Metadata ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Streaming Detector Metadata ----
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN];
uint8_t stream_hist_ptr[LLC_SETS];
uint8_t streaming_phase[LLC_SETS];

// ---- Epoch for dead-counter decay ----
uint64_t epoch_counter = 0;
#define EPOCH_LEN 100000

// ---- Initialization ----
void InitReplacementState() {
    memset(dead_ctr, 1, sizeof(dead_ctr)); // initialize as weakly dead
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    memset(streaming_phase, 0, sizeof(streaming_phase));
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    memset(is_bip_leader, 0, sizeof(is_bip_leader));
    psel = (1 << 9); // midpoint: 512
    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS/2 + i] = 1;
    }
}

// ---- Streaming Detector ----
bool update_streaming_phase(uint32_t set, uint64_t paddr) {
    uint8_t ptr = stream_hist_ptr[set];
    stream_addr_hist[set][ptr] = paddr;
    stream_hist_ptr[set] = (ptr + 1) % STREAM_HIST_LEN;
    if (ptr < STREAM_HIST_LEN - 1)
        return false; // not enough history yet
    int64_t ref_delta = (int64_t)stream_addr_hist[set][1] - (int64_t)stream_addr_hist[set][0];
    int match = 0;
    for (int i = 2; i < STREAM_HIST_LEN; ++i) {
        int64_t d = (int64_t)stream_addr_hist[set][i] - (int64_t)stream_addr_hist[set][i-1];
        if (d == ref_delta) match++;
    }
    streaming_phase[set] = (match >= STREAM_HIST_LEN - 2) ? 1 : 0;
    return (streaming_phase[set] != 0);
}

// ---- Victim Selection ----
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // First, prioritize blocks predicted dead (dead_ctr==3)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;

    // Otherwise, LRU (lowest dead_ctr)
    uint32_t victim = 0;
    uint8_t min_dead = dead_ctr[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (dead_ctr[set][way] < min_dead) {
            min_dead = dead_ctr[set][way];
            victim = way;
        }
    }
    return victim;
}

// ---- Update Replacement State ----
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
    epoch_counter++;
    // --- Streaming phase detection ---
    bool streaming = update_streaming_phase(set, paddr);

    // --- Dead-block update on hit/miss ---
    if (hit) {
        // On hit, block is alive: decrement deadness (to min 0)
        if (dead_ctr[set][way] > 0)
            dead_ctr[set][way]--;
    } else {
        // On miss, block is likely dead: increment deadness (to max 3)
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // --- DIP insertion depth selection ---
    uint8_t insertion_way = LLC_WAYS - 1; // default: insert at LRU
    bool use_bip = false;
    if (is_lip_leader[set]) {
        use_bip = false;
    } else if (is_bip_leader[set]) {
        use_bip = true;
    } else {
        use_bip = (psel < (1 << 9)); // psel < 512: favor LIP, else BIP
    }

    // In BIP, 1/32 inserts at MRU, rest at LRU.
    if (use_bip && (rand() % 32 == 0))
        insertion_way = 0; // MRU

    // --- Streaming phase: always insert at LRU, mark dead ---
    if (streaming) {
        insertion_way = LLC_WAYS - 1;
        dead_ctr[set][way] = 3; // max deadness
    } else {
        // If block recently reused (dead_ctr<=1), favor MRU when possible
        if (dead_ctr[set][way] <= 1)
            insertion_way = 0;
    }

    // --- Insert block at selected position ---
    // Note: this function is called after victim selection; "way" is the chosen victim.
    dead_ctr[set][way] = streaming ? 3 : 1; // new fill: weak dead unless streaming

    // --- DIP PSEL update ---
    if (is_lip_leader[set]) {
        if (hit && psel < 1023) psel++;
    } else if (is_bip_leader[set]) {
        if (hit && psel > 0) psel--;
    }

    // --- Dead-block epoch decay (every EPOCH_LEN accesses) ---
    if (epoch_counter % EPOCH_LEN == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--; // decay toward alive
    }
}

// ---- Print end-of-simulation statistics ----
void PrintStats() {
    int dead_blocks = 0, total_blocks = 0, streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (streaming_phase[s]) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w] == 3) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "DDH-PRS Policy: DIP-Deadblock Hybrid + Phase-Responsive Streaming" << std::endl;
    std::cout << "Blocks predicted dead (dead_ctr==3): " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "Sets with streaming detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// ---- Print periodic (heartbeat) statistics ----
void PrintStats_Heartbeat() {
    int dead_blocks = 0, total_blocks = 0, streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (streaming_phase[s]) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_ctr[s][w] == 3) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}