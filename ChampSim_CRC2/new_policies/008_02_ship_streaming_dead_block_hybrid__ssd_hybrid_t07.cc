#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 5-bit signature table, 2-bit outcome counters ---
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES 2048
uint8_t ship_counter[SHIP_SIG_ENTRIES]; // 2 bits per entry
uint8_t block_signature[LLC_SETS][LLC_WAYS]; // 5 bits per block

// --- Dead-block: 2-bit per-line reuse counter ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, delta, 2-bit counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- RRIP: 2-bit RRPV ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Periodic decay for dead_block counters ---
uint64_t global_tick = 0;
#define DECAY_INTERVAL 50000

// --- Helper: Get SHiP signature ---
inline uint8_t GetSignature(uint64_t PC) {
    // Hash lower bits of PC to 5 bits using CRC
    return champsim_crc2(PC) & ((1 << SHIP_SIG_BITS) - 1);
}

// --- Initialization ---
void InitReplacementState() {
    memset(ship_counter, 1, sizeof(ship_counter)); // neutral start
    memset(block_signature, 0, sizeof(block_signature));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(rrpv, 3, sizeof(rrpv));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    global_tick = 0;
}

// --- Streaming detector update ---
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

// --- Dead-block periodic decay ---
void DeadBlockDecay() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] > 0) --dead_ctr[set][way];
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
    // Prefer blocks with highest dead_ctr, then highest RRPV
    uint32_t victim = 0;
    uint8_t max_dead = 0;
    uint8_t max_rrpv = 0;

    // First pass: look for dead-blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_ctr[set][way] == 3) // most likely dead
            return way;
        if (dead_ctr[set][way] > max_dead) {
            max_dead = dead_ctr[set][way];
            victim = way;
        }
    }
    // If no block is marked dead (dead_ctr==3), use RRIP
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    // (Should not reach here)
    return victim;
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
    global_tick++;
    // Periodic dead-block decay
    if (global_tick % DECAY_INTERVAL == 0)
        DeadBlockDecay();

    // Streaming detection
    bool streaming = IsStreaming(set, paddr);

    // SHiP signature
    uint8_t sig = GetSignature(PC);

    // On hit: promote to MRU, update SHiP
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_counter[sig] < 3) ++ship_counter[sig];
        if (dead_ctr[set][way] > 0) --dead_ctr[set][way];
        return;
    }

    // On eviction: update SHiP for victim block's signature
    uint8_t victim_sig = block_signature[set][way];
    if (ship_counter[victim_sig] > 0) --ship_counter[victim_sig];
    if (dead_ctr[set][way] < 3) ++dead_ctr[set][way]; // increment dead on eviction

    // Streaming detected: bypass (do not insert) or insert at distant RRPV
    if (streaming) {
        rrpv[set][way] = 3;
        block_signature[set][way] = sig;
        return;
    }

    // SHiP outcome: insert at RRPV=1 if counter >=2, else RRPV=2 (more distant)
    if (ship_counter[sig] >= 2)
        rrpv[set][way] = 1;
    else
        rrpv[set][way] = 2;
    block_signature[set][way] = sig;

    // On fill, reset dead counter
    dead_ctr[set][way] = 0;
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SSD-Hybrid Policy: SHiP-lite + Streaming Detector + Dead-block Approx\n";
    // Optionally print SHiP outcome histogram or dead-block stats
    uint32_t ship_high = 0, ship_low = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_counter[i] >= 2) ++ship_high;
        else ++ship_low;
    }
    std::cout << "SHiP signature high outcome: " << ship_high
              << ", low outcome: " << ship_low << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print periodic dead-block stats
}