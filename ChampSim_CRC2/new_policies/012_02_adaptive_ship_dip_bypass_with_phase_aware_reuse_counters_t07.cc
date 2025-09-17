#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP: 2 bits per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DIP: 32 leader sets for LIP, 32 for BIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS];

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

// --- Per-block reuse counter: 2 bits per block, periodic decay ---
uint8_t reuse_counter[LLC_SETS][LLC_WAYS];
#define REUSE_DECAY_INTERVAL 8192

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(stream_table, 0, sizeof(stream_table));
    memset(reuse_counter, 0, sizeof(reuse_counter));
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

// --- Find victim: Prefer blocks with RRPV==3 and reuse_counter==0 ---
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
            if (rrpv[set][way] == 3 && reuse_counter[set][way] == 0)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Streaming detector ---
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

    // --- On hit: set RRPV to 0, update SHiP outcome, bump reuse_counter ---
    if (hit) {
        rrpv[set][way] = 0;
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        if (reuse_counter[set][way] < 3) reuse_counter[set][way]++;
        // Update DIP selector for leader sets
        if (is_leader_lip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_bip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- Streaming detector ---
    bool streaming = IsStreamingAccess(set, paddr);

    // --- DIP policy selection: LIP or BIP ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL >= 512);

    // --- Default insertion depth ---
    uint8_t ins_rrpv = use_lip ? 3 : ((rand() % 32) == 0 ? 0 : 3);

    // --- Streaming bypass: detected streaming, always insert at distant ---
    if (streaming)
        ins_rrpv = 3;
    else if (ship_table[sig] >= 2)
        ins_rrpv = 0; // High-reuse signature: insert at MRU

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;
    reuse_counter[set][way] = (ins_rrpv == 0) ? 2 : 1;

    // --- On eviction: update SHiP for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (rrpv[set][way] == 3 && ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;

    // --- Periodic reset of streaming counters and reuse counter decay ---
    fill_count++;
    if ((fill_count % STREAM_RESET_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (int i = 0; i < 2; ++i)
                stream_table[s][i].stream_count = 0;
    }
    if ((fill_count % REUSE_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_counter[s][w] > 0)
                    reuse_counter[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Adaptive SHiP-DIP Bypass + Phase-Aware Reuse Counters: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, SHiP histogram, streaming stats, reuse stats
}