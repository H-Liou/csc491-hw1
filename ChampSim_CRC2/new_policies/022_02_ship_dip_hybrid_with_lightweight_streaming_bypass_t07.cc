#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP: set-dueling between LIP and BIP, 8-bit PSEL, 32 leader sets ---
#define DIP_LEADER_SETS 32
#define DIP_PSEL_BITS 8
uint8_t DIP_PSEL = (1 << (DIP_PSEL_BITS - 1)); // Neutral start

inline bool is_lip_leader(uint32_t set) { return set < 16; }
inline bool is_bip_leader(uint32_t set) { return set >= 16 && set < 32; }
inline bool is_dip_follower(uint32_t set) { return set >= DIP_LEADER_SETS; }

// --- SHiP-lite: 6-bit PC signature, 2-bit counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_SIG_ENTRIES]; // 2-bit saturating counter
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // per-block signature

// --- RRPV: 2-bit per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Lightweight Streaming Detector: per-set last address and delta ---
// For each set, track last tag and last delta; if same delta repeats for N accesses, mark streaming
#define STREAM_N 6
uint64_t stream_last_tag[LLC_SETS];
int64_t stream_last_delta[LLC_SETS];
uint8_t stream_repeat_ctr[LLC_SETS];
bool stream_is_stream[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv));
    DIP_PSEL = (1 << (DIP_PSEL_BITS - 1));
    memset(stream_last_tag, 0, sizeof(stream_last_tag));
    memset(stream_last_delta, 0, sizeof(stream_last_delta));
    memset(stream_repeat_ctr, 0, sizeof(stream_repeat_ctr));
    memset(stream_is_stream, 0, sizeof(stream_is_stream));
}

// --- Victim selection: Standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // SRRIP-style victim selection: find RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // No victim, increment all RRPVs
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
    // --- SHiP-lite signature ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- Streaming Detector ---
    uint64_t this_tag = paddr >> 6;
    int64_t this_delta = this_tag - stream_last_tag[set];
    if (stream_repeat_ctr[set] == 0) {
        stream_last_delta[set] = this_delta;
        stream_repeat_ctr[set] = 1;
        stream_is_stream[set] = false;
    } else if (this_delta == stream_last_delta[set]) {
        if (stream_repeat_ctr[set] < 255) stream_repeat_ctr[set]++;
        if (stream_repeat_ctr[set] >= STREAM_N)
            stream_is_stream[set] = true;
    } else {
        stream_last_delta[set] = this_delta;
        stream_repeat_ctr[set] = 1;
        stream_is_stream[set] = false;
    }
    stream_last_tag[set] = this_tag;

    // --- On hit: update SHiP predictor and RRPV ---
    if (hit) {
        block_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = 0;
        // DIP: update PSEL for leader sets
        if (is_lip_leader(set)) {
            if (DIP_PSEL < ((1 << DIP_PSEL_BITS) - 1)) DIP_PSEL++;
        } else if (is_bip_leader(set)) {
            if (DIP_PSEL > 0) DIP_PSEL--;
        }
        return;
    }

    // --- Decide insertion policy: SHiP + DIP + Streaming ---
    uint8_t ins_rrpv = 3; // default distant (LRU)

    // 1. Streaming bypass: if streaming detected, bypass (do not insert)
    if (stream_is_stream[set]) {
        // Do not update block for this fill (simulate bypass by setting RRPV=3, which will be evicted soon)
        rrpv[set][way] = 3;
        block_sig[set][way] = sig;
        // Update SHiP predictor for victim
        uint8_t victim_sig = block_sig[set][way];
        if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;
        // DIP: update PSEL for leader sets
        if (is_lip_leader(set)) {
            if (DIP_PSEL > 0) DIP_PSEL--;
        } else if (is_bip_leader(set)) {
            if (DIP_PSEL < ((1 << DIP_PSEL_BITS) - 1)) DIP_PSEL++;
        }
        return;
    }

    // 2. SHiP-lite: MRU insert if signature is reused
    if (ship_table[sig] >= 2)
        ins_rrpv = 0; // high reuse, insert at MRU
    else {
        // 3. DIP: set-dueling between LIP and BIP
        bool lip_insert = false;
        if (is_lip_leader(set)) lip_insert = true;
        else if (is_bip_leader(set)) lip_insert = false;
        else lip_insert = (DIP_PSEL < (1 << (DIP_PSEL_BITS - 1)));
        if (lip_insert)
            ins_rrpv = 3; // LIP: insert at LRU
        else {
            // BIP: insert at MRU only every 32nd fill
            static uint32_t bip_ctr = 0;
            bip_ctr++;
            if ((bip_ctr & 0x1F) == 0)
                ins_rrpv = 0;
            else
                ins_rrpv = 3;
        }
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP predictor for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;

    // DIP: update PSEL for leader sets
    if (is_lip_leader(set)) {
        if (DIP_PSEL > 0) DIP_PSEL--;
    } else if (is_bip_leader(set)) {
        if (DIP_PSEL < ((1 << DIP_PSEL_BITS) - 1)) DIP_PSEL++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-DIP Hybrid + Streaming Bypass: Final statistics." << std::endl;
    uint32_t reused_cnt = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i] >= 2) reused_cnt++;
    std::cout << "SHiP-lite predictor: " << reused_cnt << " signatures predicted reused." << std::endl;

    uint32_t stream_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_is_stream[s])
            stream_cnt++;
    std::cout << "Streaming sets at end: " << stream_cnt << "/" << LLC_SETS << std::endl;
    std::cout << "DIP PSEL value: " << (uint32_t)DIP_PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and reuse histogram
}