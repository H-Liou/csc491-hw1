#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-Lite: 6-bit PC signature per block, 2-bit outcome counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_SIG_ENTRIES 1024 // 1 KiB table
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2 bits per entry

// Per-block PC signature
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- DRRIP set-dueling: 10-bit PSEL, 64 leader sets for SRRIP, 64 for BRRIP
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1)); // start at midpoint
#define LEADER_SETS 64
#define TOTAL_LEADER_SETS (LEADER_SETS*2)
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];

// --- RRIP bits: 2 per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: last address per set, last delta, streaming flag
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t is_streaming[LLC_SETS]; // 1 = streaming, 0 = not

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_outcome, 1, sizeof(ship_outcome)); // weak reuse by default
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(is_streaming, 0, sizeof(is_streaming));
    psel = (1 << (PSEL_BITS-1));

    // Mark leader sets for DRRIP set-dueling (SRRIP and BRRIP)
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    for (uint32_t i = 0; i < LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1; // first 64 sets are SRRIP leaders
        is_brrip_leader[i + LEADER_SETS] = 1; // next 64 sets are BRRIP leaders
    }
}

//--------------------------------------------
// Find victim in the set (RRIP)
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
            if (rrpv[set][way] < 3) rrpv[set][way]++;
    }
    return 0;
}

//--------------------------------------------
// Update replacement state
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
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_delta[set] != 0 && std::abs(delta) == std::abs(last_delta[set]) && (std::abs(delta) < 512*1024)) {
        is_streaming[set] = 1;
    } else {
        is_streaming[set] = 0;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- SHiP signature ---
    uint32_t sig = (PC ^ (PC >> 6)) & SHIP_SIG_MASK;
    ship_signature[set][way] = sig;

    // --- SHiP outcome update ---
    if (hit) {
        rrpv[set][way] = 0;
        // On hit, increment outcome counter for signature
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
    } else {
        // --- DRRIP set-dueling ---
        bool use_srrip = false;
        bool use_brrip = false;
        if (is_srrip_leader[set]) use_srrip = true;
        else if (is_brrip_leader[set]) use_brrip = true;
        else use_srrip = (psel >= (1 << (PSEL_BITS-1)));

        // --- Streaming bypass ---
        if (is_streaming[set]) {
            // Streaming: bypass (simulate by distant insertion)
            rrpv[set][way] = 3;
        } else {
            // SHiP-guided insertion
            if (ship_outcome[sig] >= 2) {
                rrpv[set][way] = 0; // strong reuse, insert close
            } else {
                // DRRIP: SRRIP (insert at 2) or BRRIP (insert at 3 with low probability)
                if (use_srrip) {
                    rrpv[set][way] = 2;
                } else if (use_brrip) {
                    // BRRIP: insert at 3 with 1/32 probability, else at 2
                    static uint32_t brrip_tick = 0;
                    if ((brrip_tick++ & 31) == 0)
                        rrpv[set][way] = 3;
                    else
                        rrpv[set][way] = 2;
                } else {
                    // Non-leader sets: follow PSEL
                    rrpv[set][way] = use_srrip ? 2 : 3;
                }
            }
        }

        // On miss, decrement outcome counter for victim's signature
        uint32_t victim_sig = ship_signature[set][way];
        if (ship_outcome[victim_sig] > 0) ship_outcome[victim_sig]--;
        // DRRIP set-dueling: update PSEL
        if (is_srrip_leader[set] && !hit) {
            if (psel < ((1 << PSEL_BITS)-1)) psel++;
        }
        if (is_brrip_leader[set] && !hit) {
            if (psel > 0) psel--;
        }
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass + DRRIP: Final statistics." << std::endl;
    // Print streaming sets count
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (is_streaming[s]) streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;
    // Print average SHiP outcome
    uint32_t sum = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        sum += ship_outcome[i];
    std::cout << "Avg SHiP outcome: " << (double)sum / SHIP_SIG_ENTRIES << std::endl;
    std::cout << "PSEL final value: " << psel << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[Heartbeat] Streaming sets: ";
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (is_streaming[s]) streaming_sets++;
    std::cout << streaming_sets << " | PSEL: " << psel << std::endl;
}