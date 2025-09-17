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

// --- Dead-block counter: 2 bits per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector: 2-bit per set, last address/delta per set ---
uint8_t stream_ctr[LLC_SETS];
uint64_t last_addr[LLC_SETS];
uint64_t last_delta[LLC_SETS];

// --- Per-block RRPV (2 bits) and signature ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- Periodic decay for SHiP counters and dead-block counters ---
uint64_t access_counter = 0;
const uint64_t DECAY_PERIOD = 100000;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_ctr, 0, sizeof(ship_ctr));
    memset(block_sig, 0, sizeof(block_sig));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
}

// --- Find victim: prefer dead blocks, otherwise RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Priority: dead blocks (dead_ctr==3), else RRIP (rrpv==3)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;

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

    // --- SHiP-lite signature ---
    uint8_t sig = (PC ^ (PC >> 6) ^ (set << 2)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: update SHiP counter, promote block, reset dead counter ---
    if (hit) {
        if (ship_ctr[set][block_sig[set][way]] < 3)
            ship_ctr[set][block_sig[set][way]]++;
        rrpv[set][way] = 0;
        dead_ctr[set][way] = 0;
        return;
    } else {
        // On miss: decay SHiP counter for victim block, increment dead counter
        if (ship_ctr[set][block_sig[set][way]] > 0)
            ship_ctr[set][block_sig[set][way]]--;
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // --- Streaming bypass: if streaming, do not fill cache ---
    bool streaming = (stream_ctr[set] >= 2);
    if (streaming) {
        // Mark block as dead and insert at RRPV=3 (effectively bypass)
        rrpv[set][way] = 3;
        block_sig[set][way] = sig;
        dead_ctr[set][way] = 3;
        return;
    }

    // --- SHiP-lite: frequent reuse signature? Insert at RRPV=0 ---
    uint8_t ins_rrpv = 3; // Default: distant
    if (ship_ctr[set][sig] >= 2)
        ins_rrpv = 0;

    // --- Dead block: if last victim block dead_ctr==3, insert new at distant ---
    if (dead_ctr[set][way] == 3)
        ins_rrpv = 3;

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;
    dead_ctr[set][way] = 0; // reset dead counter on new fill

    // --- Periodic decay for SHiP counters and dead block counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s) {
            for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
                if (ship_ctr[s][i] > 0)
                    ship_ctr[s][i]--;
            }
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
            }
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-DeadBlock Hybrid with Streaming Bypass: Final statistics." << std::endl;
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

    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] == 3)
                dead_blocks++;
    std::cout << "Final dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and SHiP signature histogram
}