#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite Metadata ---
#define SIG_BITS 6
#define SHIP_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming Detector ---
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 0–15
    uint8_t is_streaming; // 1 if monotonic detected
};
StreamDetect streamdet[LLC_SETS];

// --- PSEL for fallback insertion policy ---
#define PSEL_BITS 10
uint16_t psel;

// --- Periodic decay ---
uint64_t access_counter = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start at weak reuse
    memset(streamdet, 0, sizeof(streamdet));
    psel = (1 << (PSEL_BITS - 1));
}

// --- Streaming detector update ---
inline void update_stream_detector(uint32_t set, uint64_t paddr) {
    uint64_t last_addr = streamdet[set].last_addr;
    int64_t delta = int64_t(paddr) - int64_t(last_addr);
    if (last_addr != 0 && delta == streamdet[set].last_delta && delta != 0) {
        if (streamdet[set].stream_count < 15)
            streamdet[set].stream_count++;
    } else {
        streamdet[set].stream_count = 0;
    }
    streamdet[set].last_delta = delta;
    streamdet[set].last_addr = paddr;
    streamdet[set].is_streaming = (streamdet[set].stream_count >= 6) ? 1 : 0;
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    // Simple hash: keep lower 6 bits (can be improved if needed)
    return static_cast<uint8_t>(PC ^ (PC >> 6)) & ((1 << SIG_BITS) - 1);
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
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

// --- SHiP counter decay (periodic) ---
inline void ship_decay() {
    if ((access_counter & 0xFFF) == 0) { // every 4096 LLC accesses
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (ship_ctr[set][way] > 0)
                    ship_ctr[set][way]--;
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
    if ((access_counter & 0xFFF) == 0) ship_decay();

    // Update streaming detector
    update_stream_detector(set, paddr);

    uint8_t sig = get_signature(PC);

    // On hit: promote block, increment reuse counter
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        return;
    }

    // --- Streaming bypass logic ---
    if (streamdet[set].is_streaming) {
        // If predicted dead (low SHiP counter), bypass allocation
        if (ship_ctr[set][way] == 0) {
            // Bypass: do not allocate (simulate by setting high RRPV, no update to signature/counter)
            rrpv[set][way] = 3;
            return;
        }
        // Streaming but predicted reusable: insert at distant RRPV
        rrpv[set][way] = 3;
        ship_signature[set][way] = sig;
        ship_ctr[set][way] = 1; // modest confidence
        return;
    }

    // --- SHIP-based insertion ---
    if (ship_ctr[set][way] >= 2) {
        rrpv[set][way] = 0; // MRU for strong reuse
    } else {
        rrpv[set][way] = 3; // LRU for dead/weakly reused
    }
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // modest confidence on new insert

    // --- Fallback to PSEL (DRRIP) if signature is unknown (counter==1 default) ---
    // (Optional: can be enhanced for more adaptation)
    // If desired, can add PSEL-based bias for blocks with ctr==1, but keeping simple here.

    // No explicit DRRIP leader sets; SHiP learning replaces set-dueling.
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int streaming_sets = 0, total_blocks = 0, strong_reuse = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (streamdet[s].is_streaming) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "SHIP-SBRRIP Policy: SHiP-lite + Streaming Bypass RRIP" << std::endl;
    std::cout << "Streaming sets detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
}