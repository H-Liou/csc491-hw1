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

// --- DRRIP: 32 leader sets for SRRIP, 32 for BRRIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_srrip[LLC_SETS];
bool is_leader_brrip[LLC_SETS];

// --- SHiP-lite PC reuse table: 6-bit index, 2-bit counter per entry ---
#define PC_SIG_BITS 6
#define PC_SIG_ENTRIES (1 << PC_SIG_BITS) // 64 entries
uint8_t pc_sig_table[PC_SIG_ENTRIES]; // 2-bit saturating counter

// --- Per-block PC signature for eviction update ---
uint8_t block_pc_sig[LLC_SETS][LLC_WAYS];

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

// --- Dead-block approximation: per-block, 2-bit counter ---
uint8_t deadblock[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // all blocks start distant
    memset(pc_sig_table, 0, sizeof(pc_sig_table));
    memset(block_pc_sig, 0, sizeof(block_pc_sig));
    memset(stream_table, 0, sizeof(stream_table));
    memset(deadblock, 0, sizeof(deadblock));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_srrip[s] = true, is_leader_brrip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_srrip[s] = false, is_leader_brrip[s] = true;
        else
            is_leader_srrip[s] = false, is_leader_brrip[s] = false;
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
    // --- PC signature extraction (6 bits for global reuse table) ---
    uint8_t pc_sig = (PC ^ (paddr >> 6)) & (PC_SIG_ENTRIES - 1);

    // --- On hit: set RRPV to 0, update PC reuse table, store signature, dead-block counter ---
    if (hit) {
        rrpv[set][way] = 0;
        block_pc_sig[set][way] = pc_sig;
        if (pc_sig_table[pc_sig] < 3) pc_sig_table[pc_sig]++;
        if (deadblock[set][way] < 3) deadblock[set][way]++;
        // Set-dueling update
        if (is_leader_srrip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_brrip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- Streaming detector ---
    bool streaming = IsStreamingAccess(set, paddr);

    // --- DRRIP Insertion Policy: SRRIP or BRRIP based on set-dueling ---
    bool use_srrip = false;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_brrip[set])
        use_srrip = false;
    else
        use_srrip = (PSEL >= 512);

    uint8_t ins_rrpv = use_srrip ? 2 : ((rand() % 32) == 0 ? 2 : 3);

    // --- Streaming bypass: detected streaming, do not insert into cache ---
    if (streaming) {
        ins_rrpv = 3; // treat as distant; will be evicted soon
    } else {
        // SHiP-lite PC reuse bias: for high-reuse PCs, insert at MRU (0)
        if (pc_sig_table[pc_sig] >= 2)
            ins_rrpv = 0;
        else if (deadblock[set][way] >= 2)
            ins_rrpv = 0; // Dead-block approximation: block is live
    }

    rrpv[set][way] = ins_rrpv;
    block_pc_sig[set][way] = pc_sig;

    // --- On eviction: update PC reuse table for victim block ---
    uint8_t victim_sig = block_pc_sig[set][way];
    if (rrpv[set][way] == 3 && pc_sig_table[victim_sig] > 0)
        pc_sig_table[victim_sig]--;

    // --- Dead-block periodic decay ---
    if (deadblock[set][way] > 0)
        deadblock[set][way]--;

    // --- Periodic reset of streaming counters ---
    fill_count++;
    if ((fill_count % STREAM_RESET_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (int i = 0; i < 2; ++i)
                stream_table[s][i].stream_count = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite DRRIP with Streaming and Dead-Block Approximation: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, PC signature histogram, streaming stats, dead-block counters
}