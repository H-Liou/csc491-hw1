#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP set-dueling for LIP vs BIP ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel;
uint8_t is_leader_lip[LLC_SETS];
uint8_t is_leader_bip[LLC_SETS];

// --- SHiP-lite: 5-bit PC signature per block, 2-bit outcome counter per signature ---
#define SIG_BITS 5
#define SIG_TABLE_SIZE 1024
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // [0,31]
uint8_t sig_ctr[SIG_TABLE_SIZE];       // 2-bit saturating counter per signature

// --- Dead-block counter: 2 bits per block ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // [0,3]

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, monitors recent address deltas ---
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];      // 3-bit signed: [-4, +3]
#define STREAM_SCORE_MIN -4
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_THRESH 2       // If score >=2, treat as streaming

// --- Periodic decay for signature counters and deadblock counters ---
uint64_t access_counter = 0;
#define DECAY_PERIOD (SIG_TABLE_SIZE * 8)

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            dead_ctr[set][way] = 0;
        }
        is_leader_lip[set] = 0;
        is_leader_bip[set] = 0;
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_lip[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_bip[i] = 1;
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

    // --- SHiP-lite & deadblock update ---
    if (hit) {
        // On hit, increment signature counter (max 3)
        if (sig_ctr[sig] < 3)
            sig_ctr[sig]++;
        rrpv[set][way] = 0; // MRU on hit
        // Deadblock: reset to 0 on hit
        dead_ctr[set][way] = 0;
    } else {
        // On eviction, decrement signature counter (min 0)
        uint32_t victim_sig = block_sig[set][way];
        if (sig_ctr[victim_sig] > 0)
            sig_ctr[victim_sig]--;
        // Deadblock: increment on eviction (max 3)
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    }

    // --- Periodic decay of signature and deadblock counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
            if (sig_ctr[i] > 0)
                sig_ctr[i]--;
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (dead_ctr[set][way] > 0)
                    dead_ctr[set][way]--;
    }

    // --- Policy selection: DIP set-dueling ---
    bool use_lip;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (psel < (1 << (PSEL_BITS-1)));

    // --- Streaming-aware insertion ---
    bool is_streaming = (stream_score[set] >= STREAM_DETECT_THRESH);

    // --- Insertion depth logic ---
    if (is_streaming) {
        // Streaming detected: bypass with probability 1/4, else insert at LRU
        if ((PC ^ paddr) & 0x3) {
            rrpv[set][way] = 3; // Bypass
        } else {
            rrpv[set][way] = 2; // LRU
        }
        // Leader set: update PSEL for BIP
        if (is_leader_bip[set] && !hit)
            if (psel < ((1<<PSEL_BITS)-1)) psel++;
    }
    else if (sig_ctr[sig] >= 2 && dead_ctr[set][way] <= 1) {
        // Strong signature and not dead: insert at MRU
        rrpv[set][way] = 0;
        if (is_leader_lip[set] && !hit)
            if (psel > 0) psel--;
    }
    else if (sig_ctr[sig] == 1 || dead_ctr[set][way] == 2) {
        // Weak signature or possibly dead: fallback to DIP
        if (use_lip)
            rrpv[set][way] = 2; // LIP: LRU
        else {
            if ((PC ^ paddr) & 0x1F)
                rrpv[set][way] = 2; // BIP: LRU (most of the time)
            else
                rrpv[set][way] = 0; // BIP: MRU (rarely)
        }
    }
    else {
        // Unseen/weak signature and dead: insert at LRU
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
    std::cout << "SDSH: sig_ctr==2: " << sig2 << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SDSH: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SDSH: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
    int dead3 = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead3++;
    std::cout << "SDSH: dead_ctr==3: " << dead3 << std::endl;
    std::cout << "SDSH: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_ctr[i] == 3) sig3++;
    std::cout << "SDSH: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SDSH: Streaming sets: " << stream_sets << std::endl;
    int dead3 = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead3++;
    std::cout << "SDSH: dead_ctr==3: " << dead3 << std::endl;
    std::cout << "SDSH: PSEL: " << psel << std::endl;
}