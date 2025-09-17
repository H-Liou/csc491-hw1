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

// --- DIP set-dueling: 10-bit PSEL, 32 leader sets for LIP, 32 for BIP ---
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // initialize to midpoint
#define NUM_LEADER_SETS 32
uint8_t is_lip_leader[LLC_SETS];
uint8_t is_bip_leader[LLC_SETS];

// --- Streaming detector: per-set last address, last delta, 2-bit confidence ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_conf[LLC_SETS]; // 2-bit saturating counter

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

    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_conf, 0, sizeof(stream_conf));
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

// --- Streaming detector: update per-set state, returns true if streaming detected ---
bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    bool streaming = false;
    if (last_addr[set] != 0 && delta == last_delta[set] && delta != 0) {
        if (stream_conf[set] < 3) stream_conf[set]++;
        if (stream_conf[set] >= 2) streaming = true;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
        streaming = false;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
    return streaming;
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

    // --- Streaming detection ---
    bool streaming = IsStreaming(set, paddr);

    // --- On hit: update SHiP-lite predictor, set RRPV=0 ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++; // mark as reused
        rrpv[set][way] = 0;
        // Update PSEL for leader sets
        if (is_lip_leader[set] && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        else if (is_bip_leader[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- Streaming bypass: if streaming detected, do not insert ---
    if (streaming) {
        // Mark block as invalid (simulate bypass by setting RRPV=3 and signature=0)
        rrpv[set][way] = 3;
        block_sig[set][way] = 0;
        // Decay SHiP predictor for victim block
        uint8_t victim_sig = block_sig[set][way];
        if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;
        return;
    }

    // --- DIP set-dueling: choose insertion policy ---
    uint8_t ins_rrpv = 3; // default distant
    bool use_lip = false, use_bip = false;
    if (is_lip_leader[set]) use_lip = true;
    else if (is_bip_leader[set]) use_bip = true;
    else use_lip = (PSEL >= (1 << (PSEL_BITS - 1)));

    // --- SHiP-lite bias: if signature reused, insert at MRU ---
    if (ship_table[sig] >= 2) {
        ins_rrpv = 0;
    } else {
        // DIP: LIP inserts at 3, BIP inserts at 0 with low probability
        if (use_lip) ins_rrpv = 3;
        else if (use_bip) ins_rrpv = ((rand() % 32) == 0) ? 0 : 3; // BIP: 1/32 at 0, else 3
        else ins_rrpv = ((rand() % 32) == 0) ? 0 : 3; // follower sets use PSEL
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP-lite predictor for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;

    // Update PSEL for leader sets (already handled on hit)
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass + DIP Set-Dueling: Final statistics." << std::endl;
    uint32_t reused_cnt = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i] >= 2) reused_cnt++;
    std::cout << "SHiP-lite predictor: " << reused_cnt << " signatures predicted reused." << std::endl;
    std::cout << "Final PSEL value: " << PSEL << std::endl;
    // Streaming detector stats
    uint32_t stream_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (stream_conf[i] >= 2) stream_sets++;
    std::cout << "Sets detected streaming: " << stream_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL and streaming histogram
}