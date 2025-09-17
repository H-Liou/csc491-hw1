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

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2-bit saturating counter per signature
uint8_t block_sig[LLC_SETS][LLC_WAYS];  // 6-bit signature per block

// --- Dead-block approximation: 2-bit dead counter per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, 2-entry recent address delta table ---
struct StreamEntry {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 2-bit counter
};
StreamEntry stream_table[LLC_SETS][2];

// --- Streaming threshold parameters ---
#define STREAM_DETECT_THRESHOLD 3
#define STREAM_RESET_INTERVAL 4096
uint64_t fill_count = 0;

// --- Dead block decay parameters ---
#define DEAD_DECAY_INTERVAL 8192
uint64_t access_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // distant
    memset(ship_outcome, 0, sizeof(ship_outcome));
    memset(block_sig, 0, sizeof(block_sig));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(stream_table, 0, sizeof(stream_table));
    fill_count = 0;
    access_count = 0;
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

// --- Dead-block decay ---
void DecayDeadCounters() {
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[s][w] > 0)
                dead_ctr[s][w]--;
}

// --- Find victim: RRIP + Dead-block approximation ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks marked likely dead (dead_ctr == 0 and RRPV==3)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 && dead_ctr[set][way] == 0)
            return way;
    // Otherwise, standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
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
    access_count++;

    // SHiP signature extraction (6 bits: PC xor paddr[6:])
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    if (hit) {
        rrpv[set][way] = 0;
        block_sig[set][way] = sig;
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
        // Mark block as highly reused (dead_ctr max)
        dead_ctr[set][way] = 3;
        return;
    }

    // --- Streaming detector ---
    bool streaming = IsStreamingAccess(set, paddr);

    // --- On fill: choose insertion policy ---
    uint8_t ins_rrpv = 2; // SRRIP: insert at 2 (long re-reference)
    if (streaming) {
        ins_rrpv = 3; // bypass/evict soon
    } else {
        // SHiP bias: outcome >=2 ⇒ insert at MRU (0), outcome == 0 ⇒ insert at 3
        if (ship_outcome[sig] >= 2)
            ins_rrpv = 0;
        else if (ship_outcome[sig] == 0)
            ins_rrpv = 3;
        // Otherwise, default SRRIP
    }
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // Dead-block counter: new fills get min value
    dead_ctr[set][way] = 0;

    // --- On eviction: update SHiP outcome counter for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    // If evicted with RRPV==3 and outcome >0, decrement outcome
    if (rrpv[set][way] == 3 && ship_outcome[victim_sig] > 0)
        ship_outcome[victim_sig]--;

    // --- Periodic reset of streaming counters ---
    fill_count++;
    if ((fill_count % STREAM_RESET_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (int i = 0; i < 2; ++i)
                stream_table[s][i].stream_count = 0;
    }

    // --- Periodic decay of dead-block counters ---
    if ((access_count % DEAD_DECAY_INTERVAL) == 0)
        DecayDeadCounters();
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-SRRIP + Dead-block Decay + Streaming Bypass: Final statistics." << std::endl;
    // Optionally print SHiP outcome histogram
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, SHiP histogram, dead-block stats
}