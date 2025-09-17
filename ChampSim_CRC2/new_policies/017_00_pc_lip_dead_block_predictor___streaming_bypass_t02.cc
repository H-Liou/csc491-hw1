#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Dead-block predictor: 6-bit PC signature, 2-bit deadness counter ---
#define DBP_SIG_BITS 6
#define DBP_SIG_ENTRIES (1 << DBP_SIG_BITS)
uint8_t dbp_table[DBP_SIG_ENTRIES]; // 2-bit saturating deadness counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, 2-entry address history, 2-bit streaming counter ---
uint64_t stream_addr_hist[LLC_SETS][2]; // last two addresses per set
uint8_t stream_delta_hist[LLC_SETS][2]; // last two deltas per set (low bits)
uint8_t stream_counter[LLC_SETS];       // 2-bit saturating counter per set

// --- Periodic decay for dead-block predictor ---
uint64_t dbp_decay_tick = 0;
const uint64_t DBP_DECAY_PERIOD = 100000; // decay every 100K fills

// --- Initialization ---
void InitReplacementState() {
    memset(dbp_table, 0, sizeof(dbp_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_delta_hist, 0, sizeof(stream_delta_hist));
    memset(stream_counter, 0, sizeof(stream_counter));
    dbp_decay_tick = 0;
}

// --- Find victim: standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
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
    // --- Dead-block predictor signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (DBP_SIG_ENTRIES - 1);

    // --- Streaming detector update ---
    uint8_t cur_delta = (uint8_t)((paddr >> 6) - (stream_addr_hist[set][0] >> 6)); // block-granularity delta

    // Shift history
    stream_addr_hist[set][1] = stream_addr_hist[set][0];
    stream_addr_hist[set][0] = paddr;
    stream_delta_hist[set][1] = stream_delta_hist[set][0];
    stream_delta_hist[set][0] = cur_delta;

    // Streaming detection: if last two deltas are equal and nonzero, increment counter
    if (stream_delta_hist[set][0] == stream_delta_hist[set][1] &&
        stream_delta_hist[set][0] != 0) {
        if (stream_counter[set] < 3) stream_counter[set]++;
    } else {
        if (stream_counter[set] > 0) stream_counter[set]--;
    }

    // --- On hit: update dead-block predictor, set RRPV=0 ---
    if (hit) {
        block_sig[set][way] = sig;
        if (dbp_table[sig] > 0) dbp_table[sig]--; // mark as not dead
        rrpv[set][way] = 0;
        return;
    }

    // --- Streaming detector: if streaming detected, bypass with 1/2 probability ---
    if (stream_counter[set] >= 2) {
        if ((rand() % 2) == 0) {
            // Bypass: do not update replacement state for this fill
            return;
        }
    }

    // --- Dead-block predictor: if predicted dead, insert at RRPV=3 (LIP), else MRU ---
    uint8_t ins_rrpv = (dbp_table[sig] >= 2) ? 3 : 0;

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update dead-block predictor for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ins_rrpv == 3 && dbp_table[victim_sig] < 3)
        dbp_table[victim_sig]++; // mark as dead

    // --- Periodic decay of dead-block predictor ---
    dbp_decay_tick++;
    if (dbp_decay_tick % DBP_DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < DBP_SIG_ENTRIES; ++i) {
            if (dbp_table[i] > 0) dbp_table[i]--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "PC-LIP Dead-Block Predictor + Streaming Bypass: Final statistics." << std::endl;
    // Optionally print dead-block predictor histogram, streaming counter stats
    uint32_t dead_cnt = 0;
    for (uint32_t i = 0; i < DBP_SIG_ENTRIES; ++i)
        if (dbp_table[i] >= 2) dead_cnt++;
    std::cout << "Dead-block predictor: " << dead_cnt << " signatures predicted dead." << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming counter stats
}