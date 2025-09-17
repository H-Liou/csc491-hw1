#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 2048
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // [0,63]
uint8_t sig_ctr[SIG_TABLE_SIZE];       // 2-bit saturating counter per signature

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2-bit per block

// --- DRRIP set-dueling ---
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS-1)); // 10-bit policy selector
#define NUM_LEADER_SETS 32
std::vector<uint32_t> SRRIP_LEADER_SETS;
std::vector<uint32_t> BRRIP_LEADER_SETS;

// --- Streaming detector: per-set, monitors recent address deltas ---
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];      // 3-bit signed: [-4, +3]
#define STREAM_SCORE_MIN -4
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_THRESH 2       // If score >=2, treat as streaming

// --- Periodic decay for signature outcome counters ---
uint64_t access_counter = 0;
#define DECAY_PERIOD (SIG_TABLE_SIZE * 8)

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
        sig_ctr[i] = 1; // neutral initial value

    // Assign leader sets for DRRIP set-dueling
    SRRIP_LEADER_SETS.clear();
    BRRIP_LEADER_SETS.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        SRRIP_LEADER_SETS.push_back(i);
        BRRIP_LEADER_SETS.push_back(i + NUM_LEADER_SETS);
    }
    PSEL = (1 << (PSEL_BITS-1));
    access_counter = 0;
}

// Find victim in the set
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
    return 0; // fallback
}

// Update replacement state
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

    // --- Periodic decay of signature outcome counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
            if (sig_ctr[i] > 0)
                sig_ctr[i]--;
    }

    // --- Streaming-aware bypass ---
    bool is_streaming = (stream_score[set] >= STREAM_DETECT_THRESH);
    if (is_streaming) {
        // Streaming detected: bypass with probability 3/4, else insert at LRU
        if ((PC ^ paddr) & 0x3) {
            rrpv[set][way] = 3; // Bypass
            // No SHiP/DRRIP update for bypassed blocks
            block_sig[set][way] = sig;
            return;
        } else {
            rrpv[set][way] = 2; // Distant (LRU)
            block_sig[set][way] = sig;
            return;
        }
    }

    // --- DRRIP set-dueling insertion depth ---
    bool is_srrip_leader = false, is_brrip_leader = false;
    for (auto idx : SRRIP_LEADER_SETS)
        if (set == idx) is_srrip_leader = true;
    for (auto idx : BRRIP_LEADER_SETS)
        if (set == idx) is_brrip_leader = true;

    // SHiP-lite guides insertion for reusable blocks
    if (sig_ctr[sig] >= 2) {
        rrpv[set][way] = 0; // MRU for strong signature
    } else {
        // DRRIP set-dueling for other blocks
        if (is_srrip_leader) {
            rrpv[set][way] = 2; // SRRIP: distant (LRU)
        } else if (is_brrip_leader) {
            rrpv[set][way] = ((access_counter & 0x7) == 0) ? 2 : 3; // BRRIP: mostly LRU, sometimes distant
        } else {
            // Follower sets: use PSEL to choose
            if (PSEL >= (1 << (PSEL_BITS-1))) {
                rrpv[set][way] = 2; // SRRIP
            } else {
                rrpv[set][way] = ((access_counter & 0x7) == 0) ? 2 : 3; // BRRIP
            }
        }
    }

    // --- DRRIP set-dueling PSEL update ---
    if (!is_streaming && !hit) {
        if (is_srrip_leader && !hit) {
            if (PSEL < ((1<<PSEL_BITS)-1)) PSEL++;
        }
        if (is_brrip_leader && !hit) {
            if (PSEL > 0) PSEL--;
        }
    }

    // --- Update block's signature ---
    block_sig[set][way] = sig;
}

// Print end-of-simulation statistics
void PrintStats() {
    int sig2 = 0, sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_ctr[i] == 2) sig2++;
        if (sig_ctr[i] == 3) sig3++;
    }
    std::cout << "SDSB: sig_ctr==2: " << sig2 << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SDSB: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SDSB: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
    std::cout << "SDSB: PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_ctr[i] == 3) sig3++;
    std::cout << "SDSB: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SDSB: Streaming sets: " << stream_sets << std::endl;
    std::cout << "SDSB: PSEL: " << PSEL << std::endl;
}