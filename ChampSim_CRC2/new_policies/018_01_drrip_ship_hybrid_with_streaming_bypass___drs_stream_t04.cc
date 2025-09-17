#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- DRRIP Metadata ----
// 2-bit RRPV per block
static uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 10-bit PSEL counter for set-dueling (SRRIP vs BRRIP)
static uint16_t psel = 512; // 10 bits, initialized mid-range

// 64 leader sets: first 32 for SRRIP, next 32 for BRRIP
static const uint32_t NUM_LEADER_SETS = 64;
static uint32_t leader_sets_sr[32];
static uint32_t leader_sets_br[32];

// ---- SHiP-lite Metadata ----
// 6-bit PC signature per block
static uint8_t block_signature[LLC_SETS][LLC_WAYS]; // 6 bits/block

// 2-bit outcome counter per signature (64 entries)
static uint8_t signature_outcome[64];

// ---- Streaming Detector ----
// For each set: last address, last delta, streaming score (8 bits/set)
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_score[LLC_SETS];

// ---- Helper: hash PC to 6-bit signature ----
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// ---- Initialization ----
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(block_signature, 0, sizeof(block_signature));
    memset(signature_outcome, 1, sizeof(signature_outcome)); // weak reuse default
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_score, 0, sizeof(stream_score));

    // Pick leader sets: evenly spread across LLC_SETS
    for (uint32_t i = 0; i < 32; ++i) {
        leader_sets_sr[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
        leader_sets_br[i] = (LLC_SETS / NUM_LEADER_SETS) * (i + 32);
    }
}

// ---- Streaming Detector ----
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    if (delta == last_delta[set] && delta != 0) {
        if (stream_score[set] < 255) stream_score[set]++;
    } else {
        if (stream_score[set] > 0) stream_score[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
    // Streaming if score >= 32
    return stream_score[set] >= 32;
}

// ---- Find victim: standard RRIP ----
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Aging: increment all RRPVs < 3
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
}

// ---- Update replacement state ----
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
    // Streaming detector
    bool streaming = IsStreaming(set, paddr);

    // SHiP signature
    uint8_t sig = GetSignature(PC);

    // DRRIP set-dueling: check if this set is a leader
    bool is_sr_leader = false, is_br_leader = false;
    for (uint32_t i = 0; i < 32; ++i) {
        if (set == leader_sets_sr[i]) is_sr_leader = true;
        if (set == leader_sets_br[i]) is_br_leader = true;
    }

    // On hit: promote to MRU, update SHiP outcome
    if (hit) {
        rrpv[set][way] = 0;
        if (signature_outcome[sig] < 3) ++signature_outcome[sig];
        return;
    }

    // On miss: update SHiP outcome for victim block
    uint8_t victim_sig = block_signature[set][way];
    if (signature_outcome[victim_sig] > 0) --signature_outcome[victim_sig];

    // --- Insertion Policy ---
    // Streaming: bypass insertion (set RRPV=3, don't update signature)
    if (streaming) {
        rrpv[set][way] = 3;
        // Do not update block_signature for streaming blocks
        return;
    }

    // If strong SHiP reuse, insert at MRU (RRPV=0)
    if (signature_outcome[sig] >= 2) {
        rrpv[set][way] = 0;
    } else {
        // DRRIP: select SRRIP or BRRIP insertion
        uint8_t ins_rrpv = 2; // SRRIP: RRPV=2
        if (is_sr_leader) {
            ins_rrpv = 2; // SRRIP
        } else if (is_br_leader) {
            ins_rrpv = 3; // BRRIP (long re-reference)
        } else {
            // Use PSEL to choose policy for follower sets
            ins_rrpv = (psel >= 512) ? 2 : 3;
        }
        rrpv[set][way] = ins_rrpv;
    }
    // Track signature for inserted block
    block_signature[set][way] = sig;

    // --- DRRIP PSEL update ---
    // If this set is a leader, update PSEL based on hit/miss
    if (is_sr_leader && !hit) {
        if (psel > 0) --psel;
    } else if (is_br_leader && !hit) {
        if (psel < 1023) ++psel;
    }
}

// ---- Print statistics ----
void PrintStats() {
    uint32_t strong_sig = 0;
    for (uint32_t i = 0; i < 64; ++i)
        if (signature_outcome[i] >= 2) ++strong_sig;
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 32) ++streaming_sets;
    std::cout << "DRS-Stream Policy\n";
    std::cout << "Strong reuse signatures: " << strong_sig << " / 64\n";
    std::cout << "Streaming sets: " << streaming_sets << " / " << LLC_SETS << "\n";
    std::cout << "PSEL: " << psel << " (SRRIP if >=512, BRRIP if <512)\n";
}

// ---- Heartbeat stats ----
void PrintStats_Heartbeat() {
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 32) ++streaming_sets;
    std::cout << "[Heartbeat] Streaming sets: " << streaming_sets << " / " << LLC_SETS << "\n";
}