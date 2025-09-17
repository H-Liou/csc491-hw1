#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits per block
uint8_t signature[LLC_SETS][LLC_WAYS]; // 5 bits per block

// --- SHiP-lite signature table ---
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES 8192 // 8K entries (fits in 2 KiB)
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2 bits per signature

// --- Streaming detector ---
uint64_t last_addr[LLC_SETS];          // last accessed address per set
int8_t stream_state[LLC_SETS];         // 2 bits per set: 0=unknown, 1=streaming, 2=not streaming

// Helper: hash PC to signature
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 5) ^ (PC >> 13)) & ((1 << SHIP_SIG_BITS) - 1);
}

// Helper: index into SHiP outcome table
inline uint32_t ShipIndex(uint8_t sig) {
    return sig;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // distant
    memset(signature, 0, sizeof(signature));
    memset(ship_outcome, 1, sizeof(ship_outcome)); // neutral
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_state, 0, sizeof(stream_state));
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Classic RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
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
    // --- Streaming detector: update per-set state ---
    uint64_t addr_delta = (last_addr[set] == 0) ? 0 : std::abs((int64_t)paddr - (int64_t)last_addr[set]);
    last_addr[set] = paddr;
    // If delta is near block size (64B) or monotonically increasing, treat as streaming
    if (addr_delta == 64 || addr_delta == 128) {
        if (stream_state[set] < 2) stream_state[set]++;
    } else if (addr_delta > (64 * LLC_WAYS)) {
        if (stream_state[set] > 0) stream_state[set]--;
    }
    // Clamp state
    if (stream_state[set] < 0) stream_state[set] = 0;
    if (stream_state[set] > 2) stream_state[set] = 2;

    // --- SHiP-lite signature ---
    uint8_t sig = GetSignature(PC);
    uint32_t ship_idx = ShipIndex(sig);

    // --- On hit: update outcome counter ---
    if (hit) {
        if (ship_outcome[ship_idx] < 3) ship_outcome[ship_idx]++;
        rrpv[set][way] = 0; // protect reused block
    } else {
        if (ship_outcome[ship_idx] > 0) ship_outcome[ship_idx]--;
    }

    // --- On fill (miss): decide insertion depth and bypass ---
    if (!hit) {
        signature[set][way] = sig;
        // Streaming detected: bypass or insert at distant RRPV
        if (stream_state[set] >= 2) {
            // If streaming, bypass with 1/2 probability
            if ((rand() & 1) == 0) {
                // Mark block as invalid (simulate bypass)
                rrpv[set][way] = 3;
                return;
            } else {
                rrpv[set][way] = 3; // insert at distant
            }
        } else {
            // SHiP outcome: insert at RRPV=0 if likely reused, else at 2
            if (ship_outcome[ship_idx] >= 2)
                rrpv[set][way] = 0; // high reuse
            else
                rrpv[set][way] = 2; // neutral/low reuse
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int reused_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 0) reused_blocks++;
        if (stream_state[set] >= 2) streaming_sets++;
    }
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid Policy" << std::endl;
    std::cout << "Reused blocks: " << reused_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int reused_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 0) reused_blocks++;
        if (stream_state[set] >= 2) streaming_sets++;
    }
    std::cout << "Reused blocks (heartbeat): " << reused_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}