#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ----- SHiP-lite Metadata -----
#define SIG_BITS 6
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2 bits per block

// ----- RRIP Metadata -----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ----- DRRIP set-dueling metadata -----
#define NUM_LEADER_SETS 32
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];
uint16_t psel; // 10 bits: 0..1023

// ----- Streaming Detector Metadata -----
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN];
uint8_t stream_hist_ptr[LLC_SETS];
uint8_t stream_detected[LLC_SETS];

// ----- Initialization -----
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr));
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    memset(stream_detected, 0, sizeof(stream_detected));
    // Set up leader sets for DRRIP set-dueling
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS - 1 - i] = 1;
    }
    psel = 512; // midpoint
}

// ----- PC Signature hashing -----
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// ----- Streaming Detector: returns true if streaming detected -----
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
    return stream_detected[set];
}

// ----- Victim selection -----
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

    // RRIP: select block with max RRPV (3), else increment all RRPV
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) rrpv[set][way]++;
    }
}

// ----- Update replacement state -----
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

    // --- Streaming detector ---
    bool streaming = update_streaming(set, paddr);

    // --- SHiP update ---
    if (hit) {
        rrpv[set][way] = 0;
        // Strengthen SHiP reuse on hit
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        ship_signature[set][way] = sig;
        return;
    }
    // Weaken SHiP reuse on miss
    if (ship_ctr[set][way] > 0) ship_ctr[set][way]--;

    // --- DRRIP insertion policy selection ---
    // Leader sets choose insertion policy, others follow PSEL
    bool use_srrip = false;
    if (is_srrip_leader[set])
        use_srrip = true;
    else if (is_brrip_leader[set])
        use_srrip = false;
    else
        use_srrip = (psel >= 512);

    // --- Per-block SHiP bias ---
    // If block shows strong SHiP reuse (ctr >=2), always insert at MRU (rrpv=0)
    uint8_t insertion_rrpv;
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0;
    else if (streaming)
        insertion_rrpv = 3; // streaming: distant RRIP or bypass
    else if (use_srrip)
        insertion_rrpv = 2; // SRRIP: insert at 2
    else
        // BRRIP: insert at 3 with low probability (~1/32)
        insertion_rrpv = ((rand() & 0x1F) == 0) ? 2 : 3;

    // --- Streaming-aware bypass ---
    // If streaming detected and weak SHiP reuse, bypass (do not insert, leave invalid)
    if (streaming && ship_ctr[set][way] <= 1) {
        rrpv[set][way] = 3;
        ship_signature[set][way] = sig;
        ship_ctr[set][way] = 1; // weak reuse
        return;
    }

    // Insert block
    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // start at weak reuse

    // --- DRRIP PSEL update (only on leader sets) ---
    if (is_srrip_leader[set] && !hit) {
        if (psel < 1023) psel++; // SRRIP leader miss: increment PSEL (prefer BRRIP)
    }
    else if (is_brrip_leader[set] && !hit) {
        if (psel > 0) psel--;   // BRRIP leader miss: decrement PSEL (prefer SRRIP)
    }
}

// ----- Print end-of-simulation statistics -----
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0, streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (stream_detected[s]) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "DSSB Policy: DRRIP-SHiP Hybrid + Streaming-aware Bypass" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// ----- Print periodic (heartbeat) statistics -----
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
    std::cout << "PSEL (heartbeat): " << psel << std::endl;
}