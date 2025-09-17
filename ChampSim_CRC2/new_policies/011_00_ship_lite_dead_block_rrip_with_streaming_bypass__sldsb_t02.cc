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

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome table ---
#define PC_SIG_BITS 6
#define PC_SIG_ENTRIES (1 << PC_SIG_BITS)
uint8_t pc_outcome_table[PC_SIG_ENTRIES]; // 2-bit saturating counter
uint8_t block_pc_sig[LLC_SETS][LLC_WAYS]; // per-block PC signature

// --- Dead-block counter: 2 bits per block ---
uint8_t dead_block_ctr[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, 2-entry recent address delta table ---
struct StreamEntry {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 2-bit counter
};
StreamEntry stream_table[LLC_SETS][2];

#define STREAM_DETECT_THRESHOLD 3
#define STREAM_RESET_INTERVAL 4096
uint64_t fill_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(pc_outcome_table, 0, sizeof(pc_outcome_table));
    memset(block_pc_sig, 0, sizeof(block_pc_sig));
    memset(dead_block_ctr, 0, sizeof(dead_block_ctr));
    memset(stream_table, 0, sizeof(stream_table));
    fill_count = 0;
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

// --- Find victim: RRIP + dead-block preference ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with dead_block_ctr == 3 (max), else RRIP victim
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_block_ctr[set][way] == 3)
            return way;
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
    // --- PC signature extraction ---
    uint8_t pc_sig = (PC ^ (paddr >> 6)) & (PC_SIG_ENTRIES - 1);

    // --- On hit: set RRPV to 0, update PC outcome table, reset dead-block counter ---
    if (hit) {
        rrpv[set][way] = 0;
        block_pc_sig[set][way] = pc_sig;
        dead_block_ctr[set][way] = 0;
        if (pc_outcome_table[pc_sig] < 3) pc_outcome_table[pc_sig]++;
        return;
    }

    // --- Streaming detector ---
    bool streaming = IsStreamingAccess(set, paddr);

    // --- SHiP-lite insertion depth ---
    uint8_t ins_rrpv = 3; // default: distant
    if (!streaming && pc_outcome_table[pc_sig] >= 2)
        ins_rrpv = 0; // high-reuse PC: insert at MRU

    rrpv[set][way] = ins_rrpv;
    block_pc_sig[set][way] = pc_sig;

    // --- Dead-block counter update on eviction ---
    uint8_t victim_sig = block_pc_sig[set][way];
    if (rrpv[set][way] == 3) {
        if (dead_block_ctr[set][way] < 3) dead_block_ctr[set][way]++;
        // Decay PC outcome table for dead blocks
        if (pc_outcome_table[victim_sig] > 0) pc_outcome_table[victim_sig]--;
    }

    // --- Periodic decay of dead-block counters and streaming counters ---
    fill_count++;
    if ((fill_count % STREAM_RESET_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s) {
            for (int i = 0; i < LLC_WAYS; ++i)
                if (dead_block_ctr[s][i] > 0) dead_block_ctr[s][i]--;
            for (int i = 0; i < 2; ++i)
                stream_table[s][i].stream_count = 0;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite Dead-Block RRIP with Streaming Bypass: Final statistics." << std::endl;
    // Optionally print dead-block histogram, PC outcome table
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print dead-block stats, streaming stats
}