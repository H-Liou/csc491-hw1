#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block predictor: 2-bit counter per block ---
uint8_t dead_counter[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, 2-entry recent address delta table ---
struct StreamEntry {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 2-bit counter
};
StreamEntry stream_table[LLC_SETS][2];

// --- Streaming threshold parameters ---
#define STREAM_DETECT_THRESHOLD 3 // If stream_count reaches this, treat as streaming
#define STREAM_RESET_INTERVAL 4096 // Periodically reset stream counts
uint64_t fill_count = 0;

// --- Dead-block decay interval ---
#define DEAD_DECAY_INTERVAL 8192 // Periodically decay dead counters

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // all blocks start distant
    memset(dead_counter, 0, sizeof(dead_counter));
    memset(stream_table, 0, sizeof(stream_table));
    fill_count = 0;
}

// --- RRIP victim selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Streaming detector helper ---
bool IsStreamingAccess(uint32_t set, uint64_t paddr) {
    for (int i = 0; i < 2; ++i) {
        int64_t delta = paddr - stream_table[set][i].last_addr;
        if (stream_table[set][i].last_delta != 0 &&
            delta == stream_table[set][i].last_delta) {
            if (stream_table[set][i].stream_count < 3)
                stream_table[set][i].stream_count++;
            stream_table[set][i].last_addr = paddr;
            return (stream_table[set][i].stream_count >= STREAM_DETECT_THRESHOLD);
        }
    }
    int lru = (stream_table[set][0].last_addr <= stream_table[set][1].last_addr) ? 0 : 1;
    stream_table[set][lru].last_delta = paddr - stream_table[set][lru].last_addr;
    stream_table[set][lru].last_addr = paddr;
    stream_table[set][lru].stream_count = 1;
    return false;
}

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
    bool streaming = IsStreamingAccess(set, paddr);

    // --- On hit: set RRPV to 0, update dead-block counter ---
    if (hit) {
        rrpv[set][way] = 0;
        if (dead_counter[set][way] > 0)
            dead_counter[set][way]--;
        return;
    }

    // --- On fill: choose insertion depth based on dead-block prediction ---
    uint8_t ins_rrpv = 3; // default: distant

    if (streaming) {
        // Streaming: bypass by inserting at distant RRPV (will be evicted soon)
        ins_rrpv = 3;
    } else {
        // Dead-block prediction: if counter is 0 (recent reuse), insert at MRU
        if (dead_counter[set][way] == 0)
            ins_rrpv = 0;
        // If counter is 1, insert at 1 (middle)
        else if (dead_counter[set][way] == 1)
            ins_rrpv = 1;
        // If counter is 2 or 3, insert at 3 (dead)
        else
            ins_rrpv = 3;
    }
    rrpv[set][way] = ins_rrpv;

    // --- On fill: reset dead-block counter if reused recently, else increment (up to 3) ---
    if (dead_counter[set][way] < 3)
        dead_counter[set][way]++;

    // --- Periodic decay of dead-block counters and streaming counters ---
    fill_count++;
    if ((fill_count % DEAD_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_counter[s][w] > 0)
                    dead_counter[s][w]--;
    }
    if ((fill_count % STREAM_RESET_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (int i = 0; i < 2; ++i)
                stream_table[s][i].stream_count = 0;
    }
}

void PrintStats() {
    std::cout << "Hybrid SRRIP-DeadBlock with Streaming Bypass: Final statistics." << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print dead-block counter histogram
}