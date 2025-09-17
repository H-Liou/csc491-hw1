#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];    // 2-bit RRIP per block

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // 10-bit selector, initialized mid
bool is_srrip_leader[LLC_SETS];
bool is_brrip_leader[LLC_SETS];

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome per signature ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 2048
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // [0,63]
uint8_t sig_ctr[SIG_TABLE_SIZE];       // 2-bit saturating counter per signature

// --- Streaming detector: per-set, tracks monotonic deltas ---
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];         // 3-bit signed [-4,+3]
#define STREAM_SCORE_MIN -4
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_THRESH 2

// --- For periodic decay (SHIP outcome counters) ---
uint64_t access_counter = 0;
#define DECAY_PERIOD (SIG_TABLE_SIZE * 8)

// --- Helper: assign leader sets for DRRIP ---
void assign_leader_sets() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        is_srrip_leader[set] = false;
        is_brrip_leader[set] = false;
    }
    // Evenly spread leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = true;
        is_brrip_leader[LLC_SETS - 1 - i] = true;
    }
}

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
        }
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_ctr[i] = 1; // neutral
    PSEL = (1 << (PSEL_BITS - 1));
    assign_leader_sets();
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

    // --- SHiP signature extraction ---
    uint32_t sig = (PC ^ (paddr>>6)) & ((1<<SIG_BITS)-1);

    // --- Update SHiP outcome counters ---
    if (hit) {
        rrpv[set][way] = 0; // MRU on hit
        if (sig_ctr[sig] < 3)
            sig_ctr[sig]++;
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

    // --- DRRIP insertion depth ---
    bool use_srrip = false, use_brrip = false;
    if (is_srrip_leader[set])
        use_srrip = true;
    else if (is_brrip_leader[set])
        use_brrip = true;
    else
        use_srrip = (PSEL >= (1 << (PSEL_BITS - 1)));

    // --- Streaming bypass logic: if streaming detected, bypass with probability 1/2 ---
    bool is_streaming = (stream_score[set] >= STREAM_DETECT_THRESH);
    bool bypass = false;
    if (is_streaming) {
        // Use PC/paddr entropy for coin-flip
        if ((PC ^ paddr) & 0x1)
            bypass = true;
    }

    // --- SHiP bias: If signature has high reuse, insert at MRU regardless of DRRIP ---
    bool strong_sig = (sig_ctr[sig] >= 2);

    if (!hit) {
        // Update DRRIP PSEL on leader sets
        if (is_srrip_leader[set]) {
            if (!bypass && hit) // count only when block inserted and hit
                PSEL = (PSEL < ((1<<PSEL_BITS)-1)) ? (PSEL+1) : PSEL;
        }
        if (is_brrip_leader[set]) {
            if (!bypass && hit)
                PSEL = (PSEL > 0) ? (PSEL-1) : 0;
        }
    }

    // --- Insertion logic ---
    if (bypass && !hit) {
        // Streaming detected: bypass block (insert at RRPV=3)
        rrpv[set][way] = 3;
    }
    else if (strong_sig) {
        // SHiP bias: reusable block, insert at MRU
        rrpv[set][way] = 0;
    }
    else if (use_brrip) {
        // BRRIP: insert at distant (RRPV=2) with prob 7/8, MRU (0) with prob 1/8
        if (((PC ^ paddr) & 0x7) == 0)
            rrpv[set][way] = 0;
        else
            rrpv[set][way] = 2;
    }
    else {
        // SRRIP: insert at distant (RRPV=2)
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
    std::cout << "DSSB: sig_ctr==2: " << sig2 << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "DSSB: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "DSSB: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    int sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_ctr[i] == 3) sig3++;
    std::cout << "DSSB: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "DSSB: Streaming sets: " << stream_sets << std::endl;
}