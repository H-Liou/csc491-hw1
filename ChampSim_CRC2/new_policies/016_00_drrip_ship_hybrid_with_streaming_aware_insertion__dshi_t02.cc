#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP Metadata ---
#define PSEL_BITS 10
uint16_t PSEL = 512; // 10-bit selector, initialized to midpoint
#define NUM_LEADER_SETS 32
uint8_t is_sr_leader[LLC_SETS]; // 1 if SRRIP leader, 2 if BRRIP leader, 0 otherwise

// --- SHiP-lite Metadata ---
#define SIG_BITS 6
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming Detector Metadata ---
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN];
uint8_t stream_hist_ptr[LLC_SETS];
uint8_t stream_detected[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr));
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    memset(stream_detected, 0, sizeof(stream_detected));
    PSEL = 512;
    memset(is_sr_leader, 0, sizeof(is_sr_leader));
    // Assign leader sets (first NUM_LEADER_SETS for SRRIP, next NUM_LEADER_SETS for BRRIP)
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        is_sr_leader[i] = 1;
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        is_sr_leader[LLC_SETS - 1 - i] = 2;
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// --- Streaming Detector: returns true if streaming detected ---
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

// --- Victim selection ---
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

    // RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
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
    uint8_t sig = get_signature(PC);

    // --- Streaming detector ---
    bool streaming = update_streaming(set, paddr);

    // --- SHiP update ---
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        return;
    }

    // --- DRRIP insertion depth selection ---
    uint8_t insertion_rrpv = 2; // Default SRRIP
    if (is_sr_leader[set] == 1) { // SRRIP leader
        insertion_rrpv = 2;
    } else if (is_sr_leader[set] == 2) { // BRRIP leader
        insertion_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: 1/32 at 2, rest at 3
    } else { // follower sets
        insertion_rrpv = (PSEL >= 512) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
    }

    // --- SHiP bias: strong reuse (ctr>=2) → insert at MRU
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    // --- Streaming-aware insertion: if streaming detected, always insert at distant RRPV
    if (streaming)
        insertion_rrpv = 3;

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // weak reuse on fill

    // --- DRRIP PSEL update ---
    if (is_sr_leader[set] == 1) { // SRRIP leader
        if (hit && insertion_rrpv == 2) { // only count hits on SRRIP-inserted blocks
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        }
    } else if (is_sr_leader[set] == 2) { // BRRIP leader
        if (hit && (insertion_rrpv == 3 || insertion_rrpv == 2)) { // count hits on BRRIP-inserted blocks
            if (PSEL > 0) PSEL--;
        }
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    std::cout << "DSHI Policy: DRRIP + SHiP-lite + Streaming-aware insertion" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << std::endl;
}