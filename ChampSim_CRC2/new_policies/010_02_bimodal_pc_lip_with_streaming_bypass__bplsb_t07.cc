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

// --- Bimodal Insertion: 32 leader sets for LIP, 32 for BIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- Compact PC reuse table: 6-bit index, 2-bit counter per entry ---
#define PC_REUSE_BITS 6
#define PC_REUSE_ENTRIES (1 << PC_REUSE_BITS) // 64 entries
uint8_t pc_reuse_table[PC_REUSE_ENTRIES]; // 2-bit saturating counter
uint8_t block_pc_sig[LLC_SETS][LLC_WAYS]; // 6-bit PC signature per block

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
    memset(rrpv, 3, sizeof(rrpv)); // all blocks start distant
    memset(pc_reuse_table, 0, sizeof(pc_reuse_table));
    memset(block_pc_sig, 0, sizeof(block_pc_sig));
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
    uint8_t pc_sig = (PC ^ (paddr >> 6)) & (PC_REUSE_ENTRIES - 1);

    // --- On hit: set RRPV to 0, update PC reuse table, store signature ---
    if (hit) {
        rrpv[set][way] = 0;
        block_pc_sig[set][way] = pc_sig;
        if (pc_reuse_table[pc_sig] < 3) pc_reuse_table[pc_sig]++;
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

    // --- Bimodal Insertion Policy: LIP or BIP based on set-dueling ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL >= 512);

    uint8_t ins_rrpv = 3; // LIP: insert at distant (3)
    if (!use_lip) {
        // BIP: insert at MRU (0) 1/32 fills, else distant (3)
        ins_rrpv = ((rand() % 32) == 0) ? 0 : 3;
    }

    // --- Streaming bypass: detected streaming, do not insert into cache ---
    if (streaming) {
        ins_rrpv = 3; // treat as distant; will be evicted soon
    } else {
        // PC reuse bias: for high-reuse PCs, insert at MRU (0)
        if (pc_reuse_table[pc_sig] >= 2)
            ins_rrpv = 0;
    }

    rrpv[set][way] = ins_rrpv;
    block_pc_sig[set][way] = pc_sig;

    // --- On eviction: update PC reuse table for victim block ---
    uint8_t victim_sig = block_pc_sig[set][way];
    if (rrpv[set][way] == 3 && pc_reuse_table[victim_sig] > 0)
        pc_reuse_table[victim_sig]--;

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
    std::cout << "Bimodal-PC LIP with Streaming Bypass: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, PC reuse histogram, streaming stats
}