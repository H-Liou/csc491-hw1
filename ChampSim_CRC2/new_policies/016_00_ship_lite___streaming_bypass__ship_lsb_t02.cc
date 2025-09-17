#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-Lite: 6-bit outcome counter per PC signature (4096 entries) ---
#define SHIP_SIG_BITS 12
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_outcome[SHIP_TABLE_SIZE]; // 6-bit saturating counter

// --- Per-block PC signature ---
uint16_t block_sig[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, track last 2 address deltas ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_score[LLC_SETS]; // 3-bit score

// --- Parameters ---
#define SHIP_MAX 63
#define SHIP_MIN 0
#define SHIP_REUSE_THRESHOLD 32     // Above: insert MRU; below: insert LRU
#define STREAM_SCORE_MAX 7
#define STREAM_SCORE_BYPASS 5       // If score >=, bypass/insert at distant RRPV

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // SRRIP mid value
    memset(ship_outcome, SHIP_REUSE_THRESHOLD, sizeof(ship_outcome)); // neutral
    memset(block_sig, 0, sizeof(block_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(streaming_score, 0, sizeof(streaming_score));
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection (evict block with RRPV==3)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
    }
}

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
    // --- Streaming detector update ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_delta[set] != 0 && std::abs(delta - last_delta[set]) < 64) {
        // Near-monotonic stride detected
        if (streaming_score[set] < STREAM_SCORE_MAX)
            streaming_score[set]++;
    } else {
        if (streaming_score[set] > 0)
            streaming_score[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- SHiP signature ---
    uint16_t sig = champsim_crc2(PC) & (SHIP_TABLE_SIZE - 1);

    // --- On hit: promote to MRU, reward signature ---
    if (hit) {
        rrpv[set][way] = 0;
        block_sig[set][way] = sig;
        if (ship_outcome[sig] < SHIP_MAX)
            ship_outcome[sig]++;
    } else {
        // On miss/insert: penalize previous signature
        uint16_t victim_sig = block_sig[set][way];
        if (ship_outcome[victim_sig] > SHIP_MIN)
            ship_outcome[victim_sig]--;

        // --- Streaming bypass logic ---
        bool streaming = (streaming_score[set] >= STREAM_SCORE_BYPASS);

        // --- SHiP-guided insertion ---
        if (streaming) {
            // Streaming detected: insert at distant RRPV (3), minimize residency
            rrpv[set][way] = 3;
        } else if (ship_outcome[sig] >= SHIP_REUSE_THRESHOLD) {
            // Signature shows reuse: insert at MRU (0)
            rrpv[set][way] = 0;
        } else {
            // Signature shows dead-on-arrival: insert at LRU (3)
            rrpv[set][way] = 3;
        }
        block_sig[set][way] = sig;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int mru_inserts = 0, lru_inserts = 0, streaming_inserts = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            uint8_t v = rrpv[set][way];
            if (v == 0) mru_inserts++;
            if (v == 3) lru_inserts++;
        }
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (streaming_score[set] >= STREAM_SCORE_BYPASS) streaming_inserts++;
    std::cout << "SHiP-LSB: MRU inserts: " << mru_inserts
              << ", LRU inserts: " << lru_inserts
              << ", Streaming sets: " << streaming_inserts << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (streaming_score[set] >= STREAM_SCORE_BYPASS) streaming_sets++;
    std::cout << "SHiP-LSB: Streaming sets: " << streaming_sets << std::endl;
}