#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_TABLE_SIZE]; // 2-bit reuse counter per signature

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits per block
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- DRRIP set-dueling: 32 leader sets for SRRIP, 32 for BRRIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_srrip[LLC_SETS];
bool is_leader_brrip[LLC_SETS];

// --- Streaming detector: per-set last address, delta, and monotonic counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_score[LLC_SETS]; // 3 bits per set

#define STREAM_SCORE_MAX 7
#define STREAM_DETECT_THRES 6

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 1, sizeof(ship_table)); // neutral initial value
    memset(rrpv, 3, sizeof(rrpv));
    memset(block_sig, 0, sizeof(block_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_score, 0, sizeof(stream_score));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_srrip[s] = true, is_leader_brrip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_srrip[s] = false, is_leader_brrip[s] = true;
        else
            is_leader_srrip[s] = false, is_leader_brrip[s] = false;
    }
    PSEL = 512;
}

// --- Find victim: RRIP, prefer block with RRPV==3 ---
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
    // --- Streaming detector update ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_score[set] < STREAM_SCORE_MAX)
            stream_score[set]++;
    } else {
        if (stream_score[set] > 0)
            stream_score[set]--;
    }
    last_addr[set] = paddr;
    last_delta[set] = delta;

    // --- SHiP signature ---
    uint8_t sig = (PC ^ paddr) & SHIP_SIG_MASK;

    // --- On hit: set RRPV to 0, update SHiP outcome counter ---
    if (hit) {
        rrpv[set][way] = 0;
        block_sig[set][way] = sig;
        // Positive feedback: increment outcome counter (max 3)
        if (ship_table[sig] < 3) ship_table[sig]++;
        // DRRIP set-dueling update
        if (is_leader_srrip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_brrip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- On fill: choose insertion policy ---
    bool use_srrip = false;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_brrip[set])
        use_srrip = false;
    else
        use_srrip = (PSEL >= 512);

    // Streaming phase: if detected, insert at distant RRPV or bypass
    bool streaming = (stream_score[set] >= STREAM_DETECT_THRES);
    uint8_t ins_rrpv = 2; // default SRRIP

    if (streaming) {
        ins_rrpv = 3; // streaming: insert at distant RRPV
        // Optionally: bypass fill (do not insert), but here just insert at RRPV=3
    } else {
        // SHiP insertion depth: if signature shows low reuse, insert at distant RRPV
        if (ship_table[sig] == 0)
            ins_rrpv = 3;
        else if (!use_srrip) {
            // BRRIP: insert at 3 except 1/32 fills at 2
            ins_rrpv = ((rand() % 32) == 0) ? 2 : 3;
        }
    }
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP outcome counter for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    // Negative feedback: decrement outcome counter (min 0)
    if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;

    // DRRIP set-dueling update: negative feedback
    if (is_leader_srrip[set]) {
        if (PSEL > 0) PSEL--;
    } else if (is_leader_brrip[set]) {
        if (PSEL < 1023) PSEL++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass DRRIP: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
    // Optionally print SHiP table histogram
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print SHiP table histogram, PSEL, streaming scores
}