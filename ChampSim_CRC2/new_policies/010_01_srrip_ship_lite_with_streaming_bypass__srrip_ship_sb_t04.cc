#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- SHiP-lite Metadata ---
#define SIG_BITS 5
#define SHIP_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 5-bit per block
uint8_t ship_ctr[LLC_SETS][32];             // 2-bit per signature (32 possible signatures)

// --- Streaming Detector Metadata ---
uint64_t last_addr[LLC_SETS];           // Last accessed address per set
int64_t last_delta[LLC_SETS];           // Last address delta per set
uint8_t stream_ctr[LLC_SETS];           // 3-bit saturating counter per set

#define STREAM_THRESHOLD 5               // Counter value to trigger streaming mode
#define STREAM_MAX 7                     // Max counter value

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start at weak reuse
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 5)) & ((1 << SIG_BITS) - 1));
}

// --- Streaming Detector Update ---
inline void update_streaming_detector(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    if (last_addr[set] == 0) {
        stream_ctr[set] = 0;
    } else {
        if (delta == last_delta[set] && delta != 0) {
            if (stream_ctr[set] < STREAM_MAX) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
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
    // Update streaming detector
    update_streaming_detector(set, paddr);

    // Compute PC signature
    uint8_t sig = get_signature(PC);

    // On hit: promote block, increment SHiP counter
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][sig] < 3) ship_ctr[set][sig]++;
        return;
    }

    // --- Streaming bypass/insertion logic ---
    bool streaming = (stream_ctr[set] >= STREAM_THRESHOLD);

    // --- SHiP bias: if strong reuse, override and insert at MRU ---
    uint8_t insertion_rrpv = 3; // Default distant insertion
    if (ship_ctr[set][sig] >= 2)
        insertion_rrpv = 0; // Insert at MRU

    // Streaming: if detected, insert at distant RRPV or bypass if possible
    if (streaming) {
        insertion_rrpv = 3; // Insert at LRU (could bypass if possible)
        // Optional: bypass if all blocks are valid and rrpv < 3
        // But for simplicity, just insert at distant RRPV
    }

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;

    // Reset SHiP counter for new block
    ship_ctr[set][sig] = 1;
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_reuse = 0, streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            uint8_t sig = ship_signature[s][w];
            if (ship_ctr[s][sig] == 3) strong_reuse++;
        }
        if (stream_ctr[s] >= STREAM_THRESHOLD) streaming_sets++;
    }
    std::cout << "SRRIP-SHiP-SB Policy: SRRIP + SHiP-lite + Streaming Bypass" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Sets in streaming mode: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            uint8_t sig = ship_signature[s][w];
            if (ship_ctr[s][sig] == 3) strong_reuse++;
        }
        if (stream_ctr[s] >= STREAM_THRESHOLD) streaming_sets++;
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}