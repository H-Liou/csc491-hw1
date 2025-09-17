#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: per-line PC signature (6 bits) ----
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// ---- SHiP outcome table: 4096 entries, 2 bits each ----
#define SHIP_ENTRIES 4096
uint8_t ship_ctr[SHIP_ENTRIES]; // 2 bits per entry

// ---- Streaming detector: 2 bits per set for streaming confidence ----
uint8_t stream_conf[LLC_SETS]; // 2 bits per set

// ---- Streaming detector: last address per set ----
uint64_t last_addr[LLC_SETS];

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

// Helper: hash PC to 6 bits
inline uint16_t get_pc_sig(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F; // 6 bits
}

// Helper: hash PC to SHiP table index (12 bits)
inline uint16_t get_ship_idx(uint64_t PC) {
    return (PC ^ (PC >> 13) ^ (PC >> 23)) & 0xFFF; // 12 bits
}

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // SRRIP default insertion
            pc_sig[set][way] = 0;
        }
        stream_conf[set] = 0;
        last_addr[set] = 0;
    }
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        ship_ctr[i] = 1; // weakly dead
    access_counter = 0;
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

    // RRIP: select block with max RRPV (3)
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
    access_counter++;

    // ---- SHiP signature and outcome update ----
    uint16_t sig = get_pc_sig(PC);
    uint16_t ship_idx = get_ship_idx(PC);

    if (hit) {
        // On hit, increase reuse confidence for signature
        if (ship_ctr[ship_idx] < 3)
            ship_ctr[ship_idx]++;
        rrpv[set][way] = 0; // promote to MRU
    } else {
        // On miss, decrease reuse confidence
        if (ship_ctr[ship_idx] > 0)
            ship_ctr[ship_idx]--;
    }
    pc_sig[set][way] = sig;

    // ---- Streaming detector: update confidence ----
    uint64_t addr = paddr >> 6; // block address
    uint64_t delta = (last_addr[set] > 0) ? (addr > last_addr[set] ? addr - last_addr[set] : last_addr[set] - addr) : 0;
    last_addr[set] = addr;

    // If delta is small and monotonic (1 or -1), increase confidence; else decrease
    if (delta == 1) {
        if (stream_conf[set] < 3) stream_conf[set]++;
    } else if (delta > 0 && delta < 8) {
        // Small stride, possible streaming
        if (stream_conf[set] < 3) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }

    // ---- Insertion policy ----
    if (stream_conf[set] >= 2) {
        // Streaming detected: bypass or insert at distant RRPV
        rrpv[set][way] = 3; // insert at LRU (distant)
    } else {
        // SHiP outcome: insert at MRU if high reuse, else SRRIP default
        if (ship_ctr[ship_idx] >= 2) {
            rrpv[set][way] = 0; // high reuse, insert at MRU
        } else {
            rrpv[set][way] = 2; // SRRIP default insertion
        }
    }

    // ---- Periodic decay of SHiP outcome and streaming confidence ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
            if (ship_ctr[i] > 0)
                ship_ctr[i]--;
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            if (stream_conf[set] > 0)
                stream_conf[set]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_conf[set] >= 2) streaming_sets++;
    std::cout << "SRRIP-StreamSHIP Policy: SRRIP + Streaming Detector + SHiP-Lite Hybrid" << std::endl;
    std::cout << "High-reuse signatures: " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Streaming sets (conf>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_conf[set] >= 2) streaming_sets++;
    std::cout << "High-reuse signatures (heartbeat): " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Streaming sets (conf>=2, heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}