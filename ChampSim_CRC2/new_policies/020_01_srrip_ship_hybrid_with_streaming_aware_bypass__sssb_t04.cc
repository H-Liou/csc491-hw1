#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- SRRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite Metadata ----
#define SIG_BITS 4
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 4 bits per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2 bits per block

// ---- Streaming Detector Metadata ----
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN];
uint8_t stream_hist_ptr[LLC_SETS];
uint8_t stream_detected[LLC_SETS];

// ---- Set-dueling for SRRIP/BRRIP ----
#define NUM_LEADER_SETS 32
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];
uint16_t psel; // 10 bits

// ---- Initialization ----
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr));
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    memset(stream_detected, 0, sizeof(stream_detected));
    psel = (1 << 9); // 512
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS/2 + i] = 1;
    }
}

// ---- PC Signature hashing ----
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 5)) & ((1 << SIG_BITS) - 1));
}

// ---- Streaming Detector ----
bool update_streaming(uint32_t set, uint64_t paddr) {
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
    stream_detected[set] = (match >= STREAM_HIST_LEN - 2) ? 1 : 0;
    return (stream_detected[set] != 0);
}

// ---- Victim selection ----
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

    // SRRIP: select block with max RRPV (3), else increment all RRPV
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

// ---- Update replacement state ----
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
    uint8_t sig = get_signature(PC);

    // --- Streaming detection ---
    bool streaming = update_streaming(set, paddr);

    // --- SHiP update ---
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        ship_signature[set][way] = sig;
        return;
    } else {
        if (ship_ctr[set][way] > 0) ship_ctr[set][way]--;
    }

    // --- Set-dueling for SRRIP/BRRIP ---
    uint8_t insertion_rrpv = 2; // SRRIP default: insert at distant RRPV
    bool use_brrip = false;
    if (is_srrip_leader[set]) {
        use_brrip = false;
    } else if (is_brrip_leader[set]) {
        use_brrip = true;
    } else {
        use_brrip = (psel < (1 << 9)); // favor SRRIP if psel < 512
    }
    if (use_brrip) {
        insertion_rrpv = (rand() % 100 < 5) ? 1 : 2; // BRRIP: 5% at 1, 95% at 2
    }

    // --- SHiP bias: strong reuse, insert at MRU ---
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    // --- Streaming-aware bypass ---
    if (streaming && ship_ctr[set][way] <= 1) {
        // Bypass: leave block invalid and do not update metadata
        rrpv[set][way] = 3;
        ship_signature[set][way] = sig;
        ship_ctr[set][way] = 1;
        return;
    }

    // Insert block
    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // weak reuse on fill

    // --- Set-dueling PSEL update ---
    if (is_srrip_leader[set]) {
        if (hit && psel < 1023) psel++;
    } else if (is_brrip_leader[set]) {
        if (hit && psel > 0) psel--;
    }
}

// ---- Print end-of-simulation statistics ----
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0, streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (stream_detected[s]) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "SSSB Policy: SRRIP-SHiP Hybrid + Streaming-Aware Bypass" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Sets with streaming detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// ---- Print periodic (heartbeat) statistics ----
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0, streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (stream_detected[s]) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}