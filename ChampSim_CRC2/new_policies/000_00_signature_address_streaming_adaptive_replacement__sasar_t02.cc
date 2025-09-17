#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2 bits/line: RRPV
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 5 bits/line: PC signature
uint8_t pc_sig[LLC_SETS][LLC_WAYS];

// SHiP table: 2K entries, 2 bits/counter
#define SHIP_TABLE_SIZE 2048
uint8_t ship_table[SHIP_TABLE_SIZE];

// Streaming detector: 2 bytes/set
struct StreamDetect {
    int16_t last_delta;
    uint8_t stream_count;
    bool streaming;
};
StreamDetect stream_detect[LLC_SETS];

// Helper: hash PC to 5 bits
inline uint8_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 7) ^ (PC >> 13)) & 0x1F;
}

// Helper: hash signature to SHiP table index
inline uint16_t ship_index(uint8_t sig) {
    return sig;
}

// Helper: hash set for streaming detection
inline uint32_t set_hash(uint32_t set) {
    return set;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // Initialize to distant
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // Neutral reuse
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        stream_detect[s].last_delta = 0;
        stream_detect[s].stream_count = 0;
        stream_detect[s].streaming = false;
    }
}

// --- Victim selection: SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
    }
}

// --- Streaming detector update ---
void update_streaming(uint32_t set, uint64_t paddr) {
    int16_t delta = (int16_t)(paddr - stream_detect[set].last_delta);
    if (stream_detect[set].last_delta != 0) {
        if (delta == stream_detect[set].last_delta) {
            if (stream_detect[set].stream_count < 15)
                stream_detect[set].stream_count++;
        } else {
            if (stream_detect[set].stream_count > 0)
                stream_detect[set].stream_count--;
        }
        stream_detect[set].streaming = (stream_detect[set].stream_count >= 8);
    }
    stream_detect[set].last_delta = (int16_t)(paddr & 0xFFFF);
}

// --- Replacement state update ---
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
    uint8_t sig = get_signature(PC);
    uint16_t idx = ship_index(sig);

    // Update streaming detector
    update_streaming(set, paddr);

    // On hit: promote to MRU, increment SHiP counter
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_table[idx] < 3)
            ship_table[idx]++;
    } else {
        // On fill: decide bypass/insertion depth
        bool is_streaming = stream_detect[set].streaming;
        uint8_t ship_score = ship_table[idx];

        pc_sig[set][way] = sig;

        // Streaming + low SHiP score: bypass
        if (is_streaming && ship_score == 0) {
            // Mark as invalid (simulate bypass: never filled)
            rrpv[set][way] = 3;
        } else {
            // SHiP high reuse: MRU insert
            if (ship_score >= 2)
                rrpv[set][way] = 0;
            else
                rrpv[set][way] = 2; // Distant insert
        }
    }

    // On eviction: decay SHiP counter if not reused
    if (!hit) {
        uint8_t evict_sig = pc_sig[set][way];
        uint16_t evict_idx = ship_index(evict_sig);
        if (ship_table[evict_idx] > 0)
            ship_table[evict_idx]--;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SASAR: SHiP table (reuse counters) summary:" << std::endl;
    int reused = 0, total = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_table[i] >= 2) reused++;
        total++;
    }
    std::cout << "High-reuse signatures: " << reused << " / " << total << std::endl;
}

void PrintStats_Heartbeat() {
    // Optional: print streaming sets count
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_detect[s].streaming) streaming_sets++;
    std::cout << "SASAR: Streaming sets: " << streaming_sets << std::endl;
}