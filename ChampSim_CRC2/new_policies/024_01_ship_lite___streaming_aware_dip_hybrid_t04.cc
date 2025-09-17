#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit signature table per set, 2-bit counter per entry ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 per set
uint8_t ship_ctr[LLC_SETS][SHIP_SIG_ENTRIES]; // 2-bit per entry

// --- DIP: 8-bit PSEL, 32 leader sets for LIP/BIP ---
#define NUM_LEADER_SETS 32
#define PSEL_BITS 8
uint8_t is_leader_set[LLC_SETS]; // 0: normal, 1: LIP leader, 2: BIP leader
uint16_t PSEL = 1 << (PSEL_BITS - 1);

// --- Streaming detector: 2-bit per set, last address/delta per set ---
uint8_t stream_ctr[LLC_SETS];
uint64_t last_addr[LLC_SETS];
uint64_t last_delta[LLC_SETS];

// --- Per-block RRPV (2 bits) and signature ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- Periodic decay for SHiP counters ---
uint64_t access_counter = 0;
const uint64_t DECAY_PERIOD = 100000;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_ctr, 0, sizeof(ship_ctr));
    memset(block_sig, 0, sizeof(block_sig));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(is_leader_set, 0, sizeof(is_leader_set));
    // Assign leader sets for DIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = 1; // LIP leader
        is_leader_set[LLC_SETS - 1 - i] = 2; // BIP leader
    }
    PSEL = 1 << (PSEL_BITS - 1);
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
    access_counter++;

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

    // --- Compute SHiP-lite signature ---
    uint8_t sig = (PC ^ (PC >> 6) ^ (set << 2)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: update SHiP counter, promote block ---
    if (hit) {
        if (ship_ctr[set][block_sig[set][way]] < 3)
            ship_ctr[set][block_sig[set][way]]++;
        rrpv[set][way] = 0;
        return;
    } else {
        // On miss: decay SHiP counter for victim block
        if (ship_ctr[set][block_sig[set][way]] > 0)
            ship_ctr[set][block_sig[set][way]]--;
    }

    // --- DIP insertion depth selection ---
    uint8_t ins_rrpv = 2; // Default: mid (RRIP=2)
    bool streaming = (stream_ctr[set] >= 2);

    if (streaming) {
        ins_rrpv = 3; // Streaming: insert at distant (bypass-like)
    } else {
        // Leader sets
        if (is_leader_set[set] == 1) { // LIP leader
            ins_rrpv = 3; // LIP: insert at distant
        } else if (is_leader_set[set] == 2) { // BIP leader
            ins_rrpv = (rand() % 32 == 0) ? 0 : 3; // BIP: insert at RRPV=0 with 1/32 probability
        } else {
            // Follower sets: use PSEL
            if (PSEL >= (1 << (PSEL_BITS - 1)))
                ins_rrpv = 3; // LIP
            else
                ins_rrpv = (rand() % 32 == 0) ? 0 : 3; // BIP
        }
    }

    // --- SHiP-lite: override insertion for reused signatures ---
    if (!streaming && ship_ctr[set][sig] >= 2)
        ins_rrpv = 0; // Frequent reuse: insert at RRPV=0

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- DIP PSEL update for leader sets ---
    if (is_leader_set[set] == 1) { // LIP leader
        if (hit) {
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        } else {
            if (PSEL > 0) PSEL--;
        }
    } else if (is_leader_set[set] == 2) { // BIP leader
        if (hit) {
            if (PSEL > 0) PSEL--;
        } else {
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        }
    }

    // --- Periodic decay for SHiP counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
                if (ship_ctr[s][i] > 0)
                    ship_ctr[s][i]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming-Aware DIP Hybrid: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << "/" << LLC_SETS << std::endl;

    uint32_t high_reuse = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
            if (ship_ctr[s][i] >= 2)
                high_reuse++;
    std::cout << "High-reuse SHiP signatures: " << high_reuse << "/" << (LLC_SETS * SHIP_SIG_ENTRIES) << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and SHiP signature histogram
}