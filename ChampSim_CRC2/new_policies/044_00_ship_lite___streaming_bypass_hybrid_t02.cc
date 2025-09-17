#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS) // 64 entries per set, total 2048 sets = 2048*64 = 131072 entries, but we use global table for compactness
#define SHIP_GLOBAL_ENTRIES 2048 // 2048 entries, 8 bits each = 16 KiB
struct SHIPEntry {
    uint8_t outcome; // 2 bits: 0-3, saturating counter
    uint8_t valid;   // 1 bit
    uint8_t reserved; // padding
    uint16_t signature; // 6 bits
};
SHIPEntry ship_table[SHIP_GLOBAL_ENTRIES];

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector per set ---
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set: 0=not streaming, 3=strong streaming
uint64_t last_addr[LLC_SETS]; // last address seen per set

// Helper: hash PC to SHiP signature
inline uint16_t GetSignature(uint64_t PC) {
    // Use lower bits of PC, xor with set index for mixing
    return ((PC >> 2) ^ (PC >> 8)) & (SHIP_GLOBAL_ENTRIES - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // distant
    memset(ship_table, 0, sizeof(ship_table));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
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
    // --- Streaming detector update ---
    uint64_t addr_delta = (last_addr[set] > 0) ? (paddr - last_addr[set]) : 0;
    last_addr[set] = paddr;
    // If delta is constant (stride) or monotonic, increment stream_ctr, else decrement
    if (addr_delta == 64 || addr_delta == -64) { // 64B line stride
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }

    // --- SHiP-lite signature ---
    uint16_t sig = GetSignature(PC);
    SHIPEntry &entry = ship_table[sig];

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // protect block
        // Update SHiP outcome counter (saturate up)
        if (entry.outcome < 3) entry.outcome++;
        entry.valid = 1;
        entry.signature = sig;
    }
    // --- On miss ---
    else {
        // Streaming detected: bypass or insert at distant RRPV
        if (stream_ctr[set] == 3) {
            // Bypass: do not cache (simulate by setting block invalid)
            // But if not allowed, insert at RRPV=3 (distant)
            rrpv[set][way] = 3;
        } else {
            // SHiP outcome: if PC has good reuse, insert at RRPV=0; else at RRPV=2
            if (entry.valid && entry.outcome >= 2)
                rrpv[set][way] = 0; // protect
            else
                rrpv[set][way] = 2; // normal
        }
        // Update SHiP outcome counter (saturate down)
        if (entry.outcome > 0) entry.outcome--;
        entry.valid = 1;
        entry.signature = sig;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int protected_blocks = 0, distant_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int protected_blocks = 0, distant_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}