#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: PC Signature Table ----
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_outcome[SHIP_TABLE_SIZE]; // 2 bits per signature

// ---- Per-block PC signature ----
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// ---- Streaming Detector ----
uint64_t last_addr[LLC_SETS]; // last address accessed per set
int8_t stream_score[LLC_SETS]; // -8..7, signed 4 bits per set

// ---- Set-dueling for SHiP vs Streaming Bypass ----
#define NUM_LEADER_SETS 32
uint8_t is_ship_leader[LLC_SETS];
uint8_t is_stream_leader[LLC_SETS];
uint16_t psel; // 10 bits

// ---- Initialization ----
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_outcome, 1, sizeof(ship_outcome));
    memset(block_sig, 0, sizeof(block_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    memset(is_ship_leader, 0, sizeof(is_ship_leader));
    memset(is_stream_leader, 0, sizeof(is_stream_leader));
    psel = (1 << 9); // 512

    // Assign leader sets: first NUM_LEADER_SETS for SHiP, next NUM_LEADER_SETS for Streaming
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_ship_leader[i] = 1;
        is_stream_leader[LLC_SETS/2 + i] = 1;
    }
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

    // RRIP: select block with max RRPV (3), else increment all RRPV
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
    // --- Streaming Detector ---
    uint64_t addr_delta = (last_addr[set] == 0) ? 0 : (paddr - last_addr[set]);
    last_addr[set] = paddr;
    // If delta is small and monotonic (e.g., +64, +128), increment score; else decrement
    if (addr_delta == 64 || addr_delta == 128)
        if (stream_score[set] < 7) stream_score[set]++;
    else if (addr_delta != 0)
        if (stream_score[set] > -8) stream_score[set]--;

    // ---- SHiP-lite signature extraction ----
    uint8_t sig = (PC ^ (PC >> 6) ^ (PC >> 12)) & ((1 << SHIP_SIG_BITS) - 1);

    // ---- Set-dueling: choose SHiP or Streaming Bypass ----
    bool use_ship = false, use_stream = false;
    if (is_ship_leader[set]) {
        use_ship = true;
    } else if (is_stream_leader[set]) {
        use_stream = true;
    } else {
        use_ship = (psel < (1 << 9)); // favor SHiP if psel < 512
        use_stream = !use_ship;
    }

    // ---- On hit: update SHiP outcome, promote block ----
    if (hit) {
        if (ship_outcome[block_sig[set][way]] < 3) ship_outcome[block_sig[set][way]]++;
        rrpv[set][way] = 0; // MRU
        // Set-dueling PSEL update
        if (is_ship_leader[set]) {
            if (psel < 1023) psel++;
        } else if (is_stream_leader[set]) {
            if (psel > 0) psel--;
        }
        return;
    }

    // ---- On fill: decide insertion/bypass ----
    uint8_t insertion_rrpv = 2; // default distant
    bool bypass = false;

    if (use_stream && stream_score[set] >= 6) {
        // Streaming detected: bypass (do not cache) if no invalid block, else insert at max RRPV
        bool has_invalid = false;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (!current_set[w].valid) has_invalid = true;
        if (!has_invalid) bypass = true;
        else insertion_rrpv = 3;
    } else if (use_ship) {
        // SHiP insertion depth: outcome counter
        if (ship_outcome[sig] >= 2)
            insertion_rrpv = 0; // high reuse: MRU
        else if (ship_outcome[sig] == 1)
            insertion_rrpv = 1; // moderate reuse
        else
            insertion_rrpv = 2; // distant
    } else {
        // Fallback: DRRIP-like
        insertion_rrpv = (rand() % 100 < 5) ? 1 : 2;
    }

    // If bypass, do not update block metadata (simulate as miss)
    if (bypass) return;

    // Insert block: set RRPV, record signature
    rrpv[set][way] = insertion_rrpv;
    block_sig[set][way] = sig;
    // On fill, weakly increment SHiP outcome if not max
    if (ship_outcome[sig] < 3) ship_outcome[sig]++;
}

// ---- Print end-of-simulation statistics ----
void PrintStats() {
    int high_reuse = 0, total_sigs = 0, stream_sets = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_outcome[i] >= 2) high_reuse++;
        total_sigs++;
    }
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 6) stream_sets++;
    std::cout << "SLSB Policy: SHiP-Lite + Streaming Bypass Hybrid" << std::endl;
    std::cout << "PC signatures with high reuse: " << high_reuse << "/" << total_sigs << std::endl;
    std::cout << "Streaming sets detected: " << stream_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// ---- Print periodic (heartbeat) statistics ----
void PrintStats_Heartbeat() {
    int high_reuse = 0, total_sigs = 0, stream_sets = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_outcome[i] >= 2) high_reuse++;
        total_sigs++;
    }
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 6) stream_sets++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse << "/" << total_sigs << std::endl;
    std::cout << "Streaming sets detected (heartbeat): " << stream_sets << "/" << LLC_SETS << std::endl;
}