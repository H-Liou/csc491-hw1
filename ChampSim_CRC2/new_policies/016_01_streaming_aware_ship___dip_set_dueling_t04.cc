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

// --- Streaming detector: per-set, 2-bit delta state + last address ---
uint64_t last_addr[LLC_SETS];
uint8_t stream_score[LLC_SETS]; // 2-bit saturating counter

// --- Streaming threshold ---
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_WINDOW 32

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
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

// --- Find victim: standard SRRIP victim selection ---
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
void UpdateStreamingDetector(uint32_t set, uint64_t paddr) {
    uint64_t addr_blk = paddr >> 6; // block address
    uint64_t last_blk = last_addr[set];
    if (last_blk) {
        int64_t delta = addr_blk - last_blk;
        // If delta is +1 or -1, likely streaming
        if (delta == 1 || delta == -1) {
            if (stream_score[set] < STREAM_SCORE_MAX)
                stream_score[set]++;
        } else {
            if (stream_score[set] > 0)
                stream_score[set]--;
        }
    }
    last_addr[set] = addr_blk;
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
    UpdateStreamingDetector(set, paddr);

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

    // --- Streaming bypass/insertion logic ---
    bool is_streaming = (stream_score[set] >= 2);

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
        // BIP: insert at MRU (RRPV=0) with low probability (1/32), else LRU
        ins_rrpv = ((rand() % 32) == 0) ? 0 : 3;
    }

    // --- SHiP outcome: for high-reuse sigs, insert at MRU ---
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;

    // --- Streaming: if streaming, insert at LRU or bypass (do not fill) ---
    if (is_streaming) {
        // For strong streaming, bypass with probability 1/4
        if ((rand() % 4) == 0) {
            // Bypass: do not update block state, return
            return;
        }
        // Otherwise, force distant insertion
        ins_rrpv = 3;
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP outcome for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ins_rrpv == 3 && ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Streaming-Aware SHiP + DIP Set-Dueling: Final statistics." << std::endl;
    std::cout << "PSEL_DIP: " << PSEL_DIP << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL_DIP, SHiP histogram, streaming stats
}