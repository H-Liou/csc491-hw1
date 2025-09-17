#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP Metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- SHiP-lite: 5-bit PC signatures, 2-bit outcome counters ---
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES 1024 // 5 bits from PC, 1024 entries
static uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2 bits per entry

// --- Streaming Detector ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Per-line Compact Reuse Counter ---
static uint8_t reuse_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Insert distant by default
    memset(ship_outcome, 1, sizeof(ship_outcome)); // Neutral start
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(reuse_ctr, 0, sizeof(reuse_ctr));
}

// --- Streaming Detector ---
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    bool streaming = false;
    if (last_delta[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) ++stream_ctr[set];
    } else {
        if (stream_ctr[set] > 0) --stream_ctr[set];
    }
    streaming = (stream_ctr[set] >= 2);
    last_delta[set] = delta;
    last_addr[set] = paddr;
    return streaming;
}

// --- SHiP-lite Signature ---
inline uint16_t GetSignature(uint64_t PC) {
    // Use lower SHIP_SIG_BITS bits of PC hash
    return champsim_crc2(PC) & (SHIP_SIG_ENTRIES - 1);
}

// --- Victim Selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer lines with lowest reuse counter, then RRPV=3
    uint32_t victim = 0;
    uint8_t min_reuse = 3;
    bool found_reuse = false;
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (reuse_ctr[set][way] == 0) {
            victim = way;
            found_reuse = true;
            break;
        }
        if (reuse_ctr[set][way] < min_reuse) {
            min_reuse = reuse_ctr[set][way];
            victim = way;
        }
    }
    if (found_reuse)
        return victim;

    // Otherwise, standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return victim;
}

// --- Update Replacement State ---
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
    // --- Streaming detection ---
    bool streaming = IsStreaming(set, paddr);

    // --- SHiP-lite signature ---
    uint16_t sig = GetSignature(PC);

    // --- Reuse counter decay (periodic, every 4096 updates) ---
    static uint64_t global_tick = 0;
    if ((global_tick++ & 4095) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_ctr[s][w] > 0) reuse_ctr[s][w]--;
    }

    if (hit) {
        // Promote to MRU, increment reuse counter
        rrpv[set][way] = 0;
        if (reuse_ctr[set][way] < 3) reuse_ctr[set][way]++;
        // Positive outcome for SHiP
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
        return;
    }

    // Negative outcome for SHiP on eviction
    if (ship_outcome[sig] > 0) ship_outcome[sig]--;

    // --- Insertion Policy (SHiP-lite + Streaming Bypass) ---
    uint8_t insert_rrpv;
    if (streaming) {
        // Streaming phase: always insert at distant RRPV, set reuse to 0
        insert_rrpv = 3;
        reuse_ctr[set][way] = 0;
    } else {
        // SHiP outcome: hot PC => MRU, cold PC => distant
        if (ship_outcome[sig] >= 2) {
            insert_rrpv = 0; // MRU
            reuse_ctr[set][way] = 2;
        } else if (ship_outcome[sig] == 1) {
            insert_rrpv = 2;
            reuse_ctr[set][way] = 1;
        } else {
            insert_rrpv = 3;
            reuse_ctr[set][way] = 0;
        }
    }
    rrpv[set][way] = insert_rrpv;
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SSC Policy: SHiP-lite + Streaming Bypass + Compact Reuse Counter\n";
    // SHiP outcome histogram
    uint32_t ship_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        ship_hist[ship_outcome[i]]++;
    std::cout << "SHiP outcome histogram: ";
    for (int i=0; i<4; ++i) std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
    // Streaming counter histogram
    uint32_t stream_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        stream_hist[stream_ctr[i]]++;
    std::cout << "Streaming counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
    // Reuse counter histogram
    uint32_t reuse_hist[4] = {0,0,0,0};
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            reuse_hist[reuse_ctr[set][way]]++;
    std::cout << "Reuse counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << reuse_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}