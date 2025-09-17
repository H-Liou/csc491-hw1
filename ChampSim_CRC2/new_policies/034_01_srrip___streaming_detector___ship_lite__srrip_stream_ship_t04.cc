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

// ---- Streaming detector: per-set address delta history (8 bits), streaming flag (1 bit) ----
uint8_t stream_hist[LLC_SETS]; // 8 bits per set, last 8 deltas
uint8_t stream_flag[LLC_SETS]; // 1 bit per set

// ---- Other bookkeeping ----
uint64_t last_addr[LLC_SETS]; // for delta computation
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

// Helper: update streaming detector
void update_streaming_detector(uint32_t set, uint64_t paddr) {
    uint64_t delta = (last_addr[set] == 0) ? 0 : (paddr - last_addr[set]);
    last_addr[set] = paddr;
    // Shift history left, insert new delta (lower 4 bits)
    stream_hist[set] = ((stream_hist[set] << 1) | ((delta < 16) ? (delta & 0xF ? 1 : 0) : 0)) & 0xFF;
    // If last 6 deltas are nonzero and similar (streaming), set flag
    int stream_cnt = 0;
    for (int i = 0; i < 6; ++i)
        if ((stream_hist[set] >> i) & 1) stream_cnt++;
    stream_flag[set] = (stream_cnt >= 5) ? 1 : 0;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 3;
            pc_sig[set][way] = 0;
        }
        stream_hist[set] = 0;
        stream_flag[set] = 0;
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

    // ---- Streaming detector update ----
    update_streaming_detector(set, paddr);

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

    // ---- Insertion policy: streaming + SHiP ----
    if (stream_flag[set]) {
        // Streaming detected: insert at LRU (RRPV=3)
        rrpv[set][way] = 3;
        // If SHiP predicts dead (ship_ctr < 1), bypass: don't insert (invalidate block)
        if (ship_ctr[ship_idx] == 0) {
            // Invalidate block (simulate bypass)
            rrpv[set][way] = 3;
            pc_sig[set][way] = 0;
            // Optionally, mark block as invalid in real implementation
        }
    } else {
        // Not streaming: SHiP biases insertion
        if (ship_ctr[ship_idx] >= 2) {
            rrpv[set][way] = 0; // high reuse, insert at MRU
        } else {
            rrpv[set][way] = 2; // medium reuse, insert at mid-RRPV
        }
    }

    // ---- Periodic decay of SHiP outcome ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
            if (ship_ctr[i] > 0)
                ship_ctr[i]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_flag[set]) streaming_sets++;
    std::cout << "SRRIP-Stream-SHiP Policy: SRRIP + Streaming Detector + SHiP-Lite" << std::endl;
    std::cout << "High-reuse signatures: " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Streaming sets detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_flag[set]) streaming_sets++;
    std::cout << "High-reuse signatures (heartbeat): " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Streaming sets detected (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}