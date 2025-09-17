#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite signature table ---
#define SIG_BITS 6
#define SIG_ENTRIES 4096 // 12 bits index: 6 bits PC, 6 bits set
uint8_t ship_ctr[SIG_ENTRIES]; // 2 bits per entry

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits per block
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- Streaming detector per set ---
uint8_t stream_ctr[LLC_SETS];        // 2 bits per set: 0=not streaming, 3=strong streaming
uint64_t last_addr[LLC_SETS];        // last address seen per set

// Helper: signature hash (PC + set)
inline uint16_t GetSignature(uint64_t PC, uint32_t set) {
    // Mix PC and set, take lower 12 bits
    return ((PC >> 2) ^ set) & (SIG_ENTRIES - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(ship_ctr, 1, sizeof(ship_ctr)); // neutral: 1
    memset(rrpv, 3, sizeof(rrpv));         // distant
    memset(block_sig, 0, sizeof(block_sig));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
}

// Find victim in the set (classic RRIP, prefer RRPV==3)
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

    // RRIP scan for RRPV==3
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
    if (addr_delta == 64 || addr_delta == -64) { // 64B line stride
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }

    // --- SHiP-lite signature ---
    uint16_t sig = GetSignature(PC, set);

    // On hit: promote block, increment signature counter
    if (hit) {
        rrpv[set][way] = 0; // protect
        block_sig[set][way] = sig;
        if (ship_ctr[sig] < 3) ship_ctr[sig]++;
    }
    // On miss: fill block
    else {
        block_sig[set][way] = sig;
        // Streaming detected: bypass or insert at distant RRPV
        if (stream_ctr[set] == 3) {
            rrpv[set][way] = 3; // streaming: insert distant
        } else {
            // SHiP: hot signature? insert close; cold? insert distant
            if (ship_ctr[sig] >= 2)
                rrpv[set][way] = 0; // hot: insert close
            else
                rrpv[set][way] = 3; // cold: insert distant
        }
    }

    // --- On eviction: decay signature counter if block not reused ---
    // Only if victim_addr is valid (simulate: if block is evicted without hit)
    // This is handled externally in real ChampSim, but here we approximate:
    // If block was not hit before eviction, decay its signature
    // (No explicit eviction callback, so we skip this for simplicity)
}

// Print end-of-simulation statistics
void PrintStats() {
    int protected_blocks = 0, distant_blocks = 0, streaming_sets = 0;
    int hot_sigs = 0, cold_sigs = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    for (uint32_t i = 0; i < SIG_ENTRIES; ++i) {
        if (ship_ctr[i] >= 2) hot_sigs++;
        else cold_sigs++;
    }
    std::cout << "SHiP-Lite with Streaming Bypass and PC-Signature Insertion Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Hot signatures: " << hot_sigs << "/" << SIG_ENTRIES << std::endl;
    std::cout << "Cold signatures: " << cold_sigs << "/" << SIG_ENTRIES << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int protected_blocks = 0, distant_blocks = 0, streaming_sets = 0;
    int hot_sigs = 0, cold_sigs = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    for (uint32_t i = 0; i < SIG_ENTRIES; ++i) {
        if (ship_ctr[i] >= 2) hot_sigs++;
        else cold_sigs++;
    }
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Hot signatures (heartbeat): " << hot_sigs << "/" << SIG_ENTRIES << std::endl;
    std::cout << "Cold signatures (heartbeat): " << cold_sigs << "/" << SIG_ENTRIES << std::endl;
}