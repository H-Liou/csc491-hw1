#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 32 leader sets for SRRIP, 32 for BRRIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_srrip[LLC_SETS];
bool is_leader_brrip[LLC_SETS];

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 entries
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

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

// --- Dead-block approximation: per-block 2-bit reuse counter ---
uint8_t dead_block[LLC_SETS][LLC_WAYS];

// --- RRPV per block (2 bits) ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(stream_table, 0, sizeof(stream_table));
    memset(dead_block, 0, sizeof(dead_block));
    memset(rrpv, 3, sizeof(rrpv)); // 3 = distant re-reference
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

// --- Find victim: RRPV + dead-block approximation ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with dead_block counter == 0
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_block[set][way] == 0)
            return way;
    }
    // Otherwise, standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
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
    // --- SHiP signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- Streaming detector ---
    bool streaming = IsStreamingAccess(set, paddr);

    // --- On hit: update SHiP outcome, dead-block counter, and RRPV ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        dead_block[set][way] = 3; // Mark as live
        rrpv[set][way] = 0; // MRU
        // Set-dueling update
        if (is_leader_srrip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_brrip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- Streaming: bypass cache ---
    if (streaming) {
        // Do not fill this block, treat as immediate eviction
        block_sig[set][way] = sig;
        dead_block[set][way] = 0;
        rrpv[set][way] = 3;
        // On eviction: update SHiP outcome for victim block
        uint8_t victim_sig = block_sig[set][way];
        if (ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
        return;
    }

    // --- DRRIP policy selection: SRRIP or BRRIP ---
    bool use_srrip = false;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_brrip[set])
        use_srrip = false;
    else
        use_srrip = (PSEL >= 512);

    // --- Decide insertion RRPV ---
    uint8_t ins_rrpv = 2; // SRRIP: insert at 2
    if (!use_srrip) {
        // BRRIP: insert at 2 with low probability, else at 3
        ins_rrpv = ((rand() % 32) == 0) ? 2 : 3;
    }

    // --- SHiP outcome: for high-reuse sigs, insert at MRU (0) ---
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;

    // --- Update block state ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;
    dead_block[set][way] = 3; // Mark as live

    // --- On eviction: update SHiP outcome for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ins_rrpv == 3 && ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;

    // --- Dead-block decay: periodically decrement all counters ---
    fill_count++;
    if ((fill_count % 4096) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_block[s][w] > 0)
                    dead_block[s][w]--;
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (int i = 0; i < 2; ++i)
                stream_table[s][i].stream_count = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP-SHiP-Lite + Streaming Bypass + Dead-Block Decay: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, SHiP histogram, streaming stats
}