#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP: 32 leader sets for LIP, 32 for BIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL_DIP = 512; // 10-bit counter
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- Streaming detector: 2-bit per set, tracks recent delta direction ---
uint8_t stream_dir[LLC_SETS]; // 0: unknown, 1: up, 2: down, 3: mixed
uint64_t last_addr[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant
    memset(stream_dir, 0, sizeof(stream_dir));
    memset(last_addr, 0, sizeof(last_addr));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_lip[s] = true, is_leader_bip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_lip[s] = false, is_leader_bip[s] = true;
        else
            is_leader_lip[s] = false, is_leader_bip[s] = false;
    }
    PSEL_DIP = 512;
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
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

// --- Streaming detector update ---
inline void UpdateStreamDir(uint32_t set, uint64_t paddr) {
    uint64_t prev = last_addr[set];
    if (prev == 0) {
        last_addr[set] = paddr;
        stream_dir[set] = 0;
        return;
    }
    int64_t delta = (int64_t)paddr - (int64_t)prev;
    if (delta == 0) {
        // No movement
        stream_dir[set] = stream_dir[set];
    } else if (delta > 0) {
        if (stream_dir[set] == 2)
            stream_dir[set] = 3; // mixed
        else if (stream_dir[set] == 0)
            stream_dir[set] = 1; // up
    } else {
        if (stream_dir[set] == 1)
            stream_dir[set] = 3; // mixed
        else if (stream_dir[set] == 0)
            stream_dir[set] = 2; // down
    }
    last_addr[set] = paddr;
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

    // --- Streaming detector update ---
    UpdateStreamDir(set, paddr);

    // --- On hit: update SHiP outcome, set RRPV=0 ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = 0;
        // DIP set-dueling update
        if (is_leader_lip[set]) {
            if (PSEL_DIP < 1023) PSEL_DIP++;
        } else if (is_leader_bip[set]) {
            if (PSEL_DIP > 0) PSEL_DIP--;
        }
        return;
    }

    // --- Streaming detector: if monotonic accesses, bypass or insert at distant ---
    bool stream_bypass = (stream_dir[set] == 1 || stream_dir[set] == 2);

    // --- DIP policy selection: LIP or BIP ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL_DIP >= 512);

    // --- Decide insertion RRPV ---
    uint8_t ins_rrpv = 3; // LIP default (insert at LRU)
    if (!use_lip) {
        // BIP: insert at MRU (0) with low probability (1/32), else LRU (3)
        ins_rrpv = ((rand() % 32) == 0) ? 0 : 3;
    }

    // --- SHiP outcome: for high-reuse sigs, insert at MRU ---
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;

    // --- Streaming detector: bypass (do not cache), or insert at LRU ---
    if (stream_bypass && ship_table[sig] < 2) {
        // streaming: insert at RRPV=3 (LRU) (effectively likely to evict immediately)
        ins_rrpv = 3;
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP outcome for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ins_rrpv == 3 && ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;

    // DIP: update PSEL on miss in leader sets
    if (is_leader_lip[set]) {
        if (PSEL_DIP < 1023) PSEL_DIP++;
    } else if (is_leader_bip[set]) {
        if (PSEL_DIP > 0) PSEL_DIP--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Streaming-Aware SHiP-Lite + DIP Set-Dueling: Final statistics." << std::endl;
    std::cout << "PSEL_DIP: " << PSEL_DIP << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL_DIP, SHiP histogram, streaming detector stats
}