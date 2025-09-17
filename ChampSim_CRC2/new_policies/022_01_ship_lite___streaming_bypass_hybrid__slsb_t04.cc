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

// ---- SHiP-lite Metadata ----
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 32
uint8_t ship_counter[SHIP_SIG_ENTRIES]; // 2 bits per signature

uint8_t line_sig[LLC_SETS][LLC_WAYS]; // 5 bits per block

// ---- Streaming Detector Metadata ----
uint64_t last_addr[LLC_SETS]; // last address per set
int32_t last_delta[LLC_SETS]; // last delta per set
uint8_t stream_score[LLC_SETS]; // 3 bits per set

#define STREAM_SCORE_MAX 7
#define STREAM_SCORE_THRESH 5

// ---- Initialization ----
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_counter, 1, sizeof(ship_counter));
    memset(line_sig, 0, sizeof(line_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_score, 0, sizeof(stream_score));
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
    int32_t delta = (last_addr[set] == 0) ? 0 : (int32_t)(paddr - last_addr[set]);
    if (last_delta[set] != 0 && delta == last_delta[set]) {
        if (stream_score[set] < STREAM_SCORE_MAX) stream_score[set]++;
    } else {
        if (stream_score[set] > 0) stream_score[set]--;
    }
    last_addr[set] = paddr;
    last_delta[set] = delta;

    // --- SHiP Signature ---
    uint8_t sig = ((PC >> 2) ^ (set)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: update SHiP counter, promote to MRU ---
    if (hit) {
        if (ship_counter[line_sig[set][way]] < 3) ship_counter[line_sig[set][way]]++;
        rrpv[set][way] = 0;
        // No further action needed
        return;
    }

    // --- On fill: update SHiP counter for victim ---
    if (current_set[way].valid) {
        uint8_t victim_sig = line_sig[set][way];
        if (ship_counter[victim_sig] > 0) ship_counter[victim_sig]--;
    }

    // --- Streaming Bypass/Insertion Depth ---
    bool streaming = (stream_score[set] >= STREAM_SCORE_THRESH);

    uint8_t insertion_rrpv = 2; // default: distant RRPV
    if (streaming) {
        insertion_rrpv = 3; // insert at max RRPV (or bypass)
        // Optional: bypass if streaming and SHiP counter is low
        if (ship_counter[sig] == 0) {
            // Simulate bypass: do not cache this block (invalidate)
            rrpv[set][way] = 3;
            line_sig[set][way] = sig;
            return;
        }
    } else {
        // SHiP-guided insertion
        if (ship_counter[sig] >= 2)
            insertion_rrpv = 0; // strong reuse, insert MRU
        else if (ship_counter[sig] == 1)
            insertion_rrpv = 2; // moderate reuse
        else
            insertion_rrpv = 3; // weak reuse, insert at max RRPV
    }

    rrpv[set][way] = insertion_rrpv;
    line_sig[set][way] = sig;
}

// ---- Print end-of-simulation statistics ----
void PrintStats() {
    int strong_reuse = 0, total_entries = 0, stream_sets = 0;
    for (int i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_counter[i] == 3) strong_reuse++;
        total_entries++;
    }
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= STREAM_SCORE_THRESH) stream_sets++;
    std::cout << "SLSB Policy: SHiP-lite + Streaming Bypass Hybrid" << std::endl;
    std::cout << "Strong reuse SHiP signatures: " << strong_reuse << "/" << total_entries << std::endl;
    std::cout << "Streaming sets: " << stream_sets << "/" << LLC_SETS << std::endl;
}

// ---- Print periodic (heartbeat) statistics ----
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_entries = 0, stream_sets = 0;
    for (int i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_counter[i] == 3) strong_reuse++;
        total_entries++;
    }
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= STREAM_SCORE_THRESH) stream_sets++;
    std::cout << "Strong reuse SHiP signatures (heartbeat): " << strong_reuse << "/" << total_entries << std::endl;
    std::cout << "Streaming sets (heartbeat): " << stream_sets << "/" << LLC_SETS << std::endl;
}