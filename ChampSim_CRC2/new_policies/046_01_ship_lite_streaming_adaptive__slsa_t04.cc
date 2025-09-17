#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP set-dueling for SRRIP vs BRRIP ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel;
uint8_t is_leader_srrip[LLC_SETS];
uint8_t is_leader_brrip[LLC_SETS];

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 2048
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // [0,63]
uint8_t sig_ctr[SIG_TABLE_SIZE];       // 2-bit saturating counter per signature

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, monitors recent address deltas ---
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];      // 3-bit signed: [-4, +3]
#define STREAM_SCORE_MIN -4
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_THRESH 2       // If score >=2, treat as streaming

// --- Periodic decay for signature counters ---
uint64_t access_counter = 0;
#define DECAY_PERIOD (SIG_TABLE_SIZE * 8)

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
        }
        is_leader_srrip[set] = 0;
        is_leader_brrip[set] = 0;
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_srrip[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_brrip[i] = 1;
    psel = (1 << (PSEL_BITS-1));
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_ctr[i] = 1; // neutral initial value
    access_counter = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
    }
}

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
    access_counter++;

    // --- Streaming detector update ---
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    if (delta == 64 || delta == -64) {
        if (stream_score[set] < STREAM_SCORE_MAX)
            stream_score[set]++;
    } else if (delta != 0) {
        if (stream_score[set] > STREAM_SCORE_MIN)
            stream_score[set]--;
    }
    last_addr[set] = paddr;

    // --- Signature extraction ---
    uint32_t sig = (PC ^ (paddr>>6)) & ((1<<SIG_BITS)-1);

    // --- SHiP-lite update ---
    if (hit) {
        // On hit, increment signature counter (max 3)
        if (sig_ctr[sig] < 3)
            sig_ctr[sig]++;
        rrpv[set][way] = 0; // MRU on hit
    } else {
        // On eviction, decrement signature counter (min 0)
        uint32_t victim_sig = block_sig[set][way];
        if (sig_ctr[victim_sig] > 0)
            sig_ctr[victim_sig]--;
    }

    // --- Periodic decay of signature counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
            if (sig_ctr[i] > 0)
                sig_ctr[i]--;
    }

    // --- Policy selection: DRRIP set-dueling ---
    bool use_srrip;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_brrip[set])
        use_srrip = false;
    else
        use_srrip = (psel < (1 << (PSEL_BITS-1)));

    // --- Streaming-aware insertion ---
    bool is_streaming = (stream_score[set] >= STREAM_DETECT_THRESH);

    // --- Insertion depth logic ---
    if (is_streaming) {
        // Streaming detected: bypass with probability 1/8, else insert at LRU
        if ((PC ^ paddr) & 0x7) {
            rrpv[set][way] = 3; // Bypass
        } else {
            rrpv[set][way] = 2; // Distant (LRU)
        }
        // Leader set: update PSEL for BRRIP
        if (is_leader_brrip[set] && !hit)
            if (psel < ((1<<PSEL_BITS)-1)) psel++;
    }
    else if (sig_ctr[sig] >= 2) {
        // Signature shows reuse: insert at MRU
        rrpv[set][way] = 0;
        if (is_leader_srrip[set] && !hit)
            if (psel > 0) psel--;
    }
    else if (sig_ctr[sig] == 1) {
        // Weak signature: fallback to DRRIP
        if (use_srrip)
            rrpv[set][way] = 2; // SRRIP: distant
        else {
            if ((PC ^ paddr) & 0x1F)
                rrpv[set][way] = 2; // BRRIP: distant (most of the time)
            else
                rrpv[set][way] = 0; // BRRIP: MRU (rarely)
        }
    }
    else {
        // Unseen/weak signature: insert at distant (LRU)
        rrpv[set][way] = 2;
    }

    // --- Update block's signature ---
    block_sig[set][way] = sig;
}

void PrintStats() {
    int sig2 = 0, sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_ctr[i] == 2) sig2++;
        if (sig_ctr[i] == 3) sig3++;
    }
    std::cout << "SLSA: sig_ctr==2: " << sig2 << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SLSA: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SLSA: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
    std::cout << "SLSA: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_ctr[i] == 3) sig3++;
    std::cout << "SLSA: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SLSA: Streaming sets: " << stream_sets << std::endl;
    std::cout << "SLSA: PSEL: " << psel << std::endl;
}