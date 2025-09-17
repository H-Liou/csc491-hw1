#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Dead-block reuse bit: 1 bit/block
uint8_t reuse_bit[LLC_SETS][LLC_WAYS];

// SHiP-lite: 5-bit signature (from PC), 2-bit outcome counter, 32K entries
const uint32_t SHIP_SIGNATURE_BITS = 5;
const uint32_t SHIP_TABLE_SIZE = 32768;
struct SHIPEntry {
    uint8_t counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// Streaming detector: 5 bits/set
struct StreamSet {
    uint64_t last_addr;
    int64_t last_stride;
    uint8_t stride_count; // up to 4
    uint8_t streaming;    // 1 if streaming detected
    uint8_t window;       // streaming window countdown
};
StreamSet stream_sets[LLC_SETS];
const uint8_t STREAM_WIN = 16;

// Helper: PC signature hash
inline uint32_t GetSignature(uint64_t PC) {
    // Simple CRC-based hash, 5 bits
    return champsim_crc2(PC, 0) & ((1 << SHIP_SIGNATURE_BITS) - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // RRIP_MAX
    memset(reuse_bit, 0, sizeof(reuse_bit));
    memset(ship_table, 0, sizeof(ship_table));
    memset(stream_sets, 0, sizeof(stream_sets));
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
    // Prefer blocks with reuse_bit==0 (dead-block approximation)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (reuse_bit[set][way] == 0 && rrpv[set][way] == 3)
            return way;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (reuse_bit[set][way] == 0)
            return way;
    // Otherwise, standard RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
    // If none, increment RRPV and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] < 3)
            rrpv[set][way]++;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
    return 0;
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
    // --- Streaming detector ---
    StreamSet &ss = stream_sets[set];
    uint64_t cur_addr = paddr >> 6; // cache line granularity
    int64_t stride = cur_addr - ss.last_addr;
    if (ss.last_addr != 0 && (stride == ss.last_stride) && (stride == 1 || stride == -1)) {
        if (ss.stride_count < 4) ss.stride_count++;
        if (ss.stride_count == 4 && !ss.streaming) {
            ss.streaming = 1;
            ss.window = STREAM_WIN;
        }
    } else {
        ss.stride_count = 0;
        ss.streaming = 0;
        ss.window = 0;
    }
    ss.last_addr = cur_addr;
    ss.last_stride = stride;
    if (ss.streaming && ss.window > 0)
        ss.window--;

    // --- SHiP-lite signature ---
    uint32_t sig = GetSignature(PC);
    SHIPEntry &entry = ship_table[((set << SHIP_SIGNATURE_BITS) ^ sig) % SHIP_TABLE_SIZE];

    if (hit) {
        // Update reuse bit: mark as reused
        reuse_bit[set][way] = 1;
        // SHiP counter: increment if possible
        if (entry.counter < 3) entry.counter++;
    } else {
        // --- Insertion policy ---
        uint8_t ins_rrpv;
        if (ss.streaming && ss.window > 0) {
            // Streaming detected: insert at RRIP_MAX (bypass)
            ins_rrpv = 3;
        } else if (entry.counter >= 2) {
            // Signature is reused: insert at near-MRU
            ins_rrpv = 1;
        } else {
            // Dead/unknown: insert at distant
            ins_rrpv = 3;
        }
        rrpv[set][way] = ins_rrpv;
        // On insertion, mark as not reused
        reuse_bit[set][way] = 0;
        // SHiP: on insertion, decay counter unless streaming
        if (!(ss.streaming && ss.window > 0) && entry.counter > 0)
            entry.counter--;
    }
    // --- Periodic decay for reuse bits (dead-block approximation) ---
    static uint64_t global_tick = 0;
    global_tick++;
    if ((global_tick & 0xFFF) == 0) { // every 4096 accesses
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            for (uint32_t s = 0; s < LLC_SETS; ++s)
                reuse_bit[s][w] = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming sets count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "SHiP-SA-DBP: Streaming sets at end: " << streaming_sets << std::endl;
    // SHiP table: distribution
    uint64_t reused = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].counter >= 2)
            reused++;
    std::cout << "SHiP-SA-DBP: SHiP reused signatures: " << reused << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count or SHiP distribution
}