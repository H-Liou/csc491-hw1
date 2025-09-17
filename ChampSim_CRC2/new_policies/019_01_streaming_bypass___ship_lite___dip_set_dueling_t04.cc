#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signature, 2-bit reuse counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating reuse counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set 1-byte history ---
int8_t stream_delta[LLC_SETS]; // last delta (signed)
uint8_t stream_streak[LLC_SETS]; // # consecutive accesses with same delta sign

// --- DIP set-dueling: 10-bit PSEL, 32 leader sets for LIP, 32 for BIP ---
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // initialize to midpoint
#define NUM_LEADER_SETS 32
uint8_t is_lip_leader[LLC_SETS];
uint8_t is_bip_leader[LLC_SETS];

// --- Last address per set for streaming detection ---
uint64_t last_addr[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv)); // all lines start as distant

    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    memset(is_bip_leader, 0, sizeof(is_bip_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        is_lip_leader[i * (LLC_SETS / NUM_LEADER_SETS)] = 1;
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        is_bip_leader[i * (LLC_SETS / NUM_LEADER_SETS) + LLC_SETS / (2 * NUM_LEADER_SETS)] = 1;
    PSEL = (1 << (PSEL_BITS - 1));

    memset(stream_delta, 0, sizeof(stream_delta));
    memset(stream_streak, 0, sizeof(stream_streak));
    memset(last_addr, 0, sizeof(last_addr));
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
    // --- SHiP-lite signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- Streaming detector: update per-set delta history ---
    int64_t delta = (int64_t)(paddr - last_addr[set]);
    if (last_addr[set] != 0) {
        int8_t sign = (delta > 0) ? 1 : ((delta < 0) ? -1 : 0);
        if (sign != 0 && sign == stream_delta[set])
            stream_streak[set]++;
        else
            stream_streak[set] = 1;
        stream_delta[set] = sign;
    }
    last_addr[set] = paddr;

    // --- On hit: update SHiP-lite predictor, set RRPV=0 ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = 0;
        // DIP set-dueling: update PSEL for leader sets
        if (is_lip_leader[set] && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        else if (is_bip_leader[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- Streaming detector: if monotonic delta streak >= 8, treat as streaming ---
    bool is_streaming = (stream_streak[set] >= 8);

    uint8_t ins_rrpv = 3; // default distant
    bool use_lip = false, use_bip = false;
    if (is_lip_leader[set]) use_lip = true;
    else if (is_bip_leader[set]) use_bip = true;
    else use_lip = (PSEL >= (1 << (PSEL_BITS - 1)));

    // --- Streaming: bypass or insert at distant RRPV ---
    if (is_streaming) {
        ins_rrpv = 3;
    } else if (ship_table[sig] >= 2) {
        ins_rrpv = 0; // SHiP-lite: predicted reuse, insert MRU
    } else {
        // DIP: LIP inserts at 3 (LRU), BIP inserts at 0 (MRU) with low probability
        if (use_lip) ins_rrpv = 3;
        else if (use_bip) ins_rrpv = ((rand() % 32) == 0) ? 0 : 3; // BIP: 1/32 at MRU, else LRU
        else ins_rrpv = ((rand() % 32) == 0) ? 0 : 3; // follower sets use PSEL
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP-lite predictor for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;

    // DIP set-dueling: update PSEL for leader sets (already done on hit)
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Streaming-Bypass + SHiP-Lite + DIP Set-Dueling: Final statistics." << std::endl;
    uint32_t reused_cnt = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i] >= 2) reused_cnt++;
    std::cout << "SHiP-lite predictor: " << reused_cnt << " signatures predicted reused." << std::endl;
    std::cout << "Final PSEL value: " << PSEL << std::endl;

    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (stream_streak[i] >= 8) streaming_sets++;
    std::cout << "Streaming sets detected: " << streaming_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and PSEL
}