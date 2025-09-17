#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_table[LLC_SETS][SHIP_TABLE_SIZE]; // 2 bits per signature per set

// Per-block: store last signature
uint8_t block_sig[LLC_SETS][LLC_WAYS];

// --- Streaming detector: 2-bit confidence, 8-bit last_addr, 8-bit last_delta per set ---
uint8_t stream_conf[LLC_SETS];
uint64_t stream_last_addr[LLC_SETS];
int16_t stream_last_delta[LLC_SETS];

// --- DIP set-dueling: 32 leader sets for LIP, 32 for BIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- RRPV: 2 bits per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 1, sizeof(ship_table)); // neutral prediction
    memset(block_sig, 0, sizeof(block_sig));
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(stream_last_addr, 0, sizeof(stream_last_addr));
    memset(stream_last_delta, 0, sizeof(stream_last_delta));
    memset(rrpv, 3, sizeof(rrpv)); // all blocks start distant

    // Assign leader sets for DIP set-dueling
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_lip[s] = true, is_leader_bip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_lip[s] = false, is_leader_bip[s] = true;
        else
            is_leader_lip[s] = false, is_leader_bip[s] = false;
    }
}

// --- Streaming detector (per-set) ---
inline bool detect_streaming(uint32_t set, uint64_t paddr) {
    int16_t delta = (int16_t)(paddr - stream_last_addr[set]);
    bool monotonic = (delta == stream_last_delta[set]) && (delta != 0);

    if (monotonic) {
        if (stream_conf[set] < 3) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    stream_last_delta[set] = delta;
    stream_last_addr[set] = paddr;

    // Streaming if confidence high
    return (stream_conf[set] >= 2);
}

// --- Find victim ---
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
    // --- Streaming detector ---
    bool is_streaming = detect_streaming(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = (uint8_t)(PC ^ (PC >> 8)) & SHIP_SIG_MASK;

    // --- On hit: update SHiP outcome counter, set RRPV to 0 ---
    if (hit) {
        if (ship_table[set][block_sig[set][way]] < 3)
            ship_table[set][block_sig[set][way]]++;
        rrpv[set][way] = 0;
        // DIP set-dueling update
        if (is_leader_lip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_bip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- Streaming: if streaming detected, bypass (do not fill) ---
    if (is_streaming) {
        rrpv[set][way] = 3; // treat as distant (could optionally not fill)
        block_sig[set][way] = sig;
        ship_table[set][sig] = 1; // reset to neutral
        return;
    }

    // --- DIP set-dueling: choose insertion policy ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL >= 512);

    // --- SHiP-based insertion depth ---
    uint8_t pred = ship_table[set][sig];
    uint8_t ins_rrpv = 2; // default: mid (SRRIP-like)

    if (pred == 3) {
        ins_rrpv = 0; // predicted highly reused: insert at MRU
    } else if (pred == 2) {
        ins_rrpv = 1; // likely reused: insert close
    } else if (pred == 1) {
        ins_rrpv = 2; // neutral: mid
    } else {
        ins_rrpv = 3; // predicted dead: insert at distant
    }

    // If using LIP, always insert at distant (LRU)
    if (use_lip)
        ins_rrpv = 3;
    // If using BIP, insert at distant except 1/32 times
    else if (!use_lip && ((rand() % 32) == 0))
        ins_rrpv = 0;

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;
    // On fill, reset SHiP outcome counter for this signature if streaming
    if (is_streaming)
        ship_table[set][sig] = 1;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming-Aware Bypass + DIP Set-Dueling: Final statistics." << std::endl;
    // Optionally print SHiP table histogram, streaming confidence, PSEL
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print SHiP table histogram, streaming confidence, PSEL
}