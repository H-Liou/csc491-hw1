#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP Metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Set Dueling (SRRIP vs BRRIP) ---
static uint8_t is_brrip_leader[LLC_SETS]; // 1 bit per set
static uint16_t psel = 512; // 10 bits

// --- Streaming Detector ---
static uint64_t last_addr[LLC_SETS];      // Last address seen per set
static int64_t last_delta[LLC_SETS];      // Last delta per set
static uint8_t stream_ctr[LLC_SETS];      // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    psel = 512;

    // Assign 32 leader sets to SRRIP (low indices), 32 to BRRIP (high indices)
    for (uint32_t i = 0; i < LLC_SETS; ++i) {
        if (i < 32) is_brrip_leader[i] = 0; // SRRIP leader
        else if (i >= LLC_SETS - 32) is_brrip_leader[i] = 1; // BRRIP leader
        // else: follower
    }
}

// --- Find victim: standard RRIP ---
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
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
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
    // --- Streaming Detector ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0) {
        if (delta == last_delta[set]) {
            if (stream_ctr[set] < 3) ++stream_ctr[set];
        } else {
            if (stream_ctr[set] > 0) --stream_ctr[set];
        }
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- On hit: promote to MRU ---
    if (hit) {
        rrpv[set][way] = 0;
        return;
    }

    // --- Set Dueling: choose insertion depth ---
    uint8_t insert_rrpv = 2; // SRRIP default: "long" re-reference
    bool use_brrip = false;
    if (is_brrip_leader[set] == 1) {
        // BRRIP leader: insert at distant (3) most times, MRU only 1/32
        use_brrip = ((rand() & 31) == 0);
        insert_rrpv = use_brrip ? 0 : 3;
    } else if (is_brrip_leader[set] == 0) {
        // SRRIP leader: always insert at 2
        insert_rrpv = 2;
    } else {
        // Follower: PSEL controls
        if (psel >= 512) {
            // SRRIP preferred
            insert_rrpv = 2;
        } else {
            use_brrip = ((rand() & 31) == 0);
            insert_rrpv = use_brrip ? 0 : 3;
        }
    }

    // --- Streaming Detector Bypass ---
    // If streaming detected (counter saturated), bypass or insert at distant
    if (stream_ctr[set] >= 3) {
        // Bypass: do not insert, just mark victim as invalid (simulate bypass)
        // In Champsim, we must insert something, so insert at max RRPV (3)
        insert_rrpv = 3;
    }

    rrpv[set][way] = insert_rrpv;

    // --- Set Dueling: update PSEL based on misses in leader sets ---
    if (is_brrip_leader[set] == 1 && !hit) {
        if (psel > 0) --psel;
    } else if (is_brrip_leader[set] == 0 && !hit) {
        if (psel < 1023) ++psel;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SRRIP + Streaming Detector Bypass Policy\n";
    std::cout << "PSEL: " << psel << std::endl;
    // Streaming detector histogram
    uint32_t hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        hist[stream_ctr[i]]++;
    std::cout << "Streaming detector histogram: ";
    for (int i=0; i<4; ++i) std::cout << hist[i] << " ";
    std::cout << std::endl;
}

// --- Heartbeat stats ---
void PrintStats_Heartbeat() {
    // No-op for brevity
}