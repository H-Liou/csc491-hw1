#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit signature per block, 2-bit outcome table ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2 bits per signature

uint8_t block_sig[LLC_SETS][LLC_WAYS];  // 6 bits per block

// --- DRRIP: 2-bit RRPV per block, 10-bit PSEL, leader sets ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];       // 2 bits per block
uint16_t PSEL = 512;                    // 10 bits, range 0-1023

// Leader set selection
#define NUM_LEADER_SETS 64
uint8_t leader_set_type[LLC_SETS];      // 0: SRRIP, 1: BRRIP, 2: normal

// --- Streaming detector: 2 bits per set, last address/delta per set ---
uint8_t stream_ctr[LLC_SETS];
uint64_t last_addr[LLC_SETS];
uint64_t last_delta[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_outcome, 1, sizeof(ship_outcome)); // Neutral start
    memset(block_sig, 0, sizeof(block_sig));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(leader_set_type, 2, sizeof(leader_set_type));

    // Assign leader sets for SRRIP and BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        leader_set_type[i] = 0; // SRRIP leader
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = 1; // BRRIP leader
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
    // Find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
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
    // --- Streaming detector: update on fill (miss only) ---
    if (!hit) {
        uint64_t delta = (last_addr[set] == 0) ? 0 : (paddr - last_addr[set]);
        if (last_addr[set] != 0 && delta == last_delta[set] && delta != 0) {
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
        last_delta[set] = delta;
        last_addr[set] = paddr;
    }

    // --- Streaming bypass logic ---
    bool streaming = (stream_ctr[set] >= 2);
    if (streaming && !hit) {
        // Streaming detected: bypass insertion (mark block as most distant)
        rrpv[set][way] = 3;
        block_sig[set][way] = 0;
        return;
    }

    // --- SHiP-lite signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- SHiP outcome update ---
    if (hit) {
        // On hit: promote block, increment outcome
        rrpv[set][way] = 0;
        if (ship_outcome[block_sig[set][way]] < 3)
            ship_outcome[block_sig[set][way]]++;
        return;
    } else {
        // On miss: decrement outcome for victim block's signature
        if (block_sig[set][way] != 0 && ship_outcome[block_sig[set][way]] > 0)
            ship_outcome[block_sig[set][way]]--;
    }

    // --- DRRIP insertion depth selection ---
    uint8_t ins_rrpv = 2; // Default SRRIP
    uint8_t set_type = leader_set_type[set];
    if (set_type == 0) { // SRRIP leader
        ins_rrpv = 2;
    } else if (set_type == 1) { // BRRIP leader
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: 1/32 near, rest distant
    } else {
        // Normal set: use PSEL to choose
        if (PSEL >= 512)
            ins_rrpv = 2;
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3;
    }

    // --- SHiP outcome bias ---
    if (ship_outcome[sig] >= 2)
        ins_rrpv = 2; // Favor near insertion for cache-friendly signatures
    else if (ship_outcome[sig] == 0)
        ins_rrpv = 3; // Distant for non-reuse signatures

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- DRRIP set-dueling PSEL update ---
    if (!hit) {
        if (set_type == 0) { // SRRIP leader
            if (PSEL < 1023) PSEL++;
        } else if (set_type == 1) { // BRRIP leader
            if (PSEL > 0) PSEL--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite DRRIP + Streaming Bypass: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << "/" << LLC_SETS << std::endl;

    uint32_t ship_high = 0, ship_low = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_outcome[i] >= 2) ship_high++;
        if (ship_outcome[i] == 0) ship_low++;
    }
    std::cout << "SHiP signatures with high reuse: " << ship_high << "/" << SHIP_SIG_ENTRIES << std::endl;
    std::cout << "SHiP signatures with low reuse: " << ship_low << "/" << SHIP_SIG_ENTRIES << std::endl;
    std::cout << "Final PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and SHiP outcome histogram
}