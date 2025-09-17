#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- DRRIP Set-Dueling Metadata ----
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t PSEL = PSEL_MAX / 2;

// Leader sets for SRRIP/BRRIP (64 total, interleaved)
#define LEADER_SETS 64
#define SRRIP_LEADER_SETS 32
#define BRRIP_LEADER_SETS 32
bool is_SRRIP_leader[LLC_SETS];
bool is_BRRIP_leader[LLC_SETS];

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite Metadata ----
#define SIG_BITS 6
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2 bits per block

// ---- Streaming Detector ----
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN]; // last 4 addresses per set
uint8_t stream_hist_ptr[LLC_SETS]; // circular pointer per set
uint8_t stream_detected[LLC_SETS]; // 1 if streaming detected

#define STREAM_DETECT_COUNT 3 // at least 3 matching deltas
#define STREAM_BYPASS_RRPV 3  // insert at distant RRPV (LRU)

// ---- Initialization ----
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // neutral reuse
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    memset(stream_detected, 0, sizeof(stream_detected));
    PSEL = PSEL_MAX / 2;
    // Assign leader sets: interleave for fairness
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        is_SRRIP_leader[s] = (s % (LLC_SETS / LEADER_SETS) == 0 && (s / (LLC_SETS / LEADER_SETS)) < SRRIP_LEADER_SETS);
        is_BRRIP_leader[s] = (s % (LLC_SETS / LEADER_SETS) == 0 && (s / (LLC_SETS / LEADER_SETS)) >= SRRIP_LEADER_SETS);
    }
}

// ---- PC Signature hashing ----
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// ---- Streaming Detector: returns true if streaming detected ----
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
    stream_detected[set] = (match >= STREAM_DETECT_COUNT - 1) ? 1 : 0;
    return stream_detected[set];
}

// ---- DRRIP Insertion Depth Decision ----
uint8_t get_drrip_insertion(uint32_t set) {
    if (is_SRRIP_leader[set]) return 2; // SRRIP: insert at RRPV=2
    if (is_BRRIP_leader[set]) return (rand() % 32 == 0) ? 2 : 3; // BRRIP: mostly LRU, rare RRPV=2
    // Follower sets: use PSEL to choose
    if (PSEL >= PSEL_MAX / 2) return 2; // SRRIP
    else return (rand() % 32 == 0) ? 2 : 3; // BRRIP
}

// ---- Find victim ----
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
        // Increment RRPVs (max 3)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
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
    // --- Streaming detector ---
    bool streaming = update_streaming(set, paddr);

    uint8_t sig = get_signature(PC);

    // --- On hit: promote, update SHiP ---
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        return;
    }

    // --- On fill: SHiP-guided insertion ---
    uint8_t ship_score = ship_ctr[set][way];
    uint8_t insertion_rrpv;
    // If streaming detected AND ship_score <=1, bypass or insert at distant RRPV
    if (streaming && ship_score <= 1)
        insertion_rrpv = STREAM_BYPASS_RRPV;
    else if (ship_score >= 2)
        insertion_rrpv = 0; // Strong reuse: insert MRU
    else
        insertion_rrpv = get_drrip_insertion(set); // DRRIP insertion

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // weak reuse on fill

    // --- DRRIP Set-Dueling: update PSEL based on leader set hits ---
    if (is_SRRIP_leader[set] && hit && PSEL < PSEL_MAX) PSEL++;
    if (is_BRRIP_leader[set] && hit && PSEL > 0) PSEL--;
}

// ---- Print end-of-simulation statistics ----
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    std::cout << "DRRIP-SHiP-SAB Policy: DRRIP set-dueling + SHiP-lite + Streaming Bypass" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "PSEL selector final value: " << PSEL << " (SRRIP if >= " << PSEL_MAX/2 << ")" << std::endl;
}

// ---- Print periodic (heartbeat) statistics ----
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