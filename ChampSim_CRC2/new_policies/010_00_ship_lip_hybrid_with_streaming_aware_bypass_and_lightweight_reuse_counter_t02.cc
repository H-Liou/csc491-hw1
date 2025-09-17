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

// --- DIP set-dueling: 32 leader sets for LIP, 32 for BIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- SHiP-lite: 5-bit PC signature per block, 2-bit outcome counter per signature ---
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 32 entries
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2-bit saturating counter per signature
uint8_t block_sig[LLC_SETS][LLC_WAYS];  // 5-bit signature per block

// --- Lightweight reuse counter: 2 bits per block ---
uint8_t reuse_counter[LLC_SETS][LLC_WAYS];

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

// --- Reuse counter decay interval ---
#define REUSE_DECAY_INTERVAL 8192

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // all blocks start distant
    memset(ship_outcome, 0, sizeof(ship_outcome));
    memset(block_sig, 0, sizeof(block_sig));
    memset(reuse_counter, 0, sizeof(reuse_counter));
    memset(stream_table, 0, sizeof(stream_table));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_lip[s] = true, is_leader_bip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_lip[s] = false, is_leader_bip[s] = true;
        else
            is_leader_lip[s] = false, is_leader_bip[s] = false;
    }
    PSEL = 512;
    fill_count = 0;
}

// --- Find victim: RRIP victim selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // RRIP victim selection: pick block with RRPV==3, else increment all and retry
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
    // --- SHiP signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: set RRPV to 0, update SHiP outcome, increment reuse counter ---
    if (hit) {
        rrpv[set][way] = 0;
        block_sig[set][way] = sig;
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
        if (reuse_counter[set][way] < 3) reuse_counter[set][way]++;
        // Set-dueling update
        if (is_leader_lip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_bip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- Streaming detector ---
    bool streaming = IsStreamingAccess(set, paddr);

    // --- On fill: choose insertion policy ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL >= 512);

    uint8_t ins_rrpv = 3; // LIP: always insert at LRU (distant)
    if (!use_lip) {
        // BIP: insert at MRU (0) 1/32 fills, else at LRU (3)
        ins_rrpv = ((rand() % 32) == 0) ? 0 : 3;
    }

    // Streaming detector: if streaming, bypass (do not insert into cache)
    if (streaming) {
        ins_rrpv = 3; // streaming: insert at distant, will be evicted soon
    } else {
        // SHiP bias: if outcome counter for sig is high, insert at 0 (MRU); if low, at ins_rrpv
        if (ship_outcome[sig] >= 2)
            ins_rrpv = 0;
        else if (ship_outcome[sig] == 0)
            ins_rrpv = 3;
    }

    // Reuse counter: if block was recently reused, insert at MRU
    if (reuse_counter[set][way] >= 2) {
        ins_rrpv = 0;
    }

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;
    reuse_counter[set][way] = 0;

    // --- On eviction: update SHiP outcome counter for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (rrpv[set][way] == 3 && ship_outcome[victim_sig] > 0)
        ship_outcome[victim_sig]--;

    // --- Periodic reset of streaming counters ---
    fill_count++;
    if ((fill_count % STREAM_RESET_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (int i = 0; i < 2; ++i)
                stream_table[s][i].stream_count = 0;
    }
    // --- Periodic decay of reuse counters ---
    if ((fill_count % REUSE_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_counter[s][w] > 0)
                    reuse_counter[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-LIP Hybrid with Streaming-Aware Bypass and Lightweight Reuse Counter: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print SHiP outcome histogram, PSEL, reuse counter stats
}