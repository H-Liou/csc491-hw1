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

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- Streaming detector: per-set, 2-entry address history, 2-bit streaming counter ---
uint64_t stream_addr_hist[LLC_SETS][2]; // last two addresses per set
uint8_t stream_delta_hist[LLC_SETS][2]; // last two deltas per set (low bits)
uint8_t stream_counter[LLC_SETS];       // 2-bit saturating counter per set

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant
    memset(is_leader_srrip, 0, sizeof(is_leader_srrip));
    memset(is_leader_brrip, 0, sizeof(is_leader_brrip));
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_delta_hist, 0, sizeof(stream_delta_hist));
    memset(stream_counter, 0, sizeof(stream_counter));
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
    // --- SHiP signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- Streaming detector update ---
    uint64_t prev_addr = stream_addr_hist[set][1];
    uint8_t prev_delta = stream_delta_hist[set][1];
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

    // --- On hit: update SHiP outcome, set RRPV=0 ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = 0;
        // Set-dueling update
        if (is_leader_srrip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_brrip[set]) {
            if (PSEL > 0) PSEL--;
        }
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
    uint8_t ins_rrpv = 2; // SRRIP default
    if (!use_srrip) {
        // BRRIP: insert at RRPV=3 with low probability (1/32), else RRPV=2
        ins_rrpv = ((rand() % 32) == 0) ? 3 : 2;
    }

    // --- SHiP outcome: for high-reuse sigs, insert at MRU ---
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;

    // --- Streaming detector: if streaming detected, insert at RRPV=3 or bypass ---
    if (stream_counter[set] >= 2) {
        // If streaming is strong, bypass with 1/2 probability, else insert at RRPV=3
        if ((rand() % 2) == 0) {
            // Bypass: do not update replacement state for this fill
            return;
        } else {
            ins_rrpv = 3;
        }
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
    std::cout << "SHiP-Lite + Streaming Detector Bypass + DRRIP Set-Dueling: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, SHiP histogram, streaming counter stats
}