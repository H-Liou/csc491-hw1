#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: Per-block 5-bit PC signature, global 2-bit outcome table (32 entries) ---
#define SIG_BITS 5
#define SIG_ENTRIES (1 << SIG_BITS)
uint8_t block_sig[LLC_SETS][LLC_WAYS];     // 5 bits per block
uint8_t sig_ctr[SIG_ENTRIES];              // 2 bits per signature

// --- DIP-style set-dueling for SRRIP vs BRRIP ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_srrip[LLC_SETS];
uint8_t is_leader_brrip[LLC_SETS];

// --- Per-set streaming detector ---
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];      // 3-bit signed: [-4, +3]
#define STREAM_SCORE_MIN -4
#define STREAM_SCORE_MAX 3
#define STREAM_DETECT_THRESH 2       // If score >=2, treat as streaming

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Periodic decay for outcome counters ---
uint64_t access_counter = 0;
#define DECAY_PERIOD (LLC_SETS * LLC_WAYS * 8)

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
    // First DUEL_LEADER_SETS sets are SRRIP-leader, next DUEL_LEADER_SETS are BRRIP-leader
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_srrip[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_brrip[i] = 1;

    psel = (1 << (PSEL_BITS-1));
    access_counter = 0;

    for (uint32_t i = 0; i < SIG_ENTRIES; ++i)
        sig_ctr[i] = 1; // neutral
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
    bool is_streaming = (stream_score[set] >= STREAM_DETECT_THRESH);

    // --- SHiP-lite signature logic ---
    uint8_t sig = (PC ^ (PC >> 5) ^ (PC >> 13)) & (SIG_ENTRIES-1);

    // On hit: reinforce signature reuse
    if (hit) {
        rrpv[set][way] = 0; // MRU
        block_sig[set][way] = sig;
        // Saturating increment outcome counter
        if (sig_ctr[sig] < 3)
            sig_ctr[sig]++;
    } else {
        // On eviction: decay outcome counter for the signature of victim block
        uint8_t victim_sig = block_sig[set][way];
        if (sig_ctr[victim_sig] > 0)
            sig_ctr[victim_sig]--;
        block_sig[set][way] = sig;
    }

    // --- Periodic decay of outcome counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SIG_ENTRIES; ++i)
            if (sig_ctr[i] > 0)
                sig_ctr[i]--;
    }

    // --- Set-dueling DIP for SRRIP vs BRRIP ---
    bool use_srrip;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_brrip[set])
        use_srrip = false;
    else
        use_srrip = (psel < (1 << (PSEL_BITS-1)));

    // --- Insertion depth logic ---
    if (is_streaming) {
        // Streaming detected: insert at distant RRPV, bypass 1/8
        if ((PC ^ paddr) & 0x7)
            rrpv[set][way] = 3; // Bypass
        else
            rrpv[set][way] = 2; // Distant
        // Update PSEL if leader set
        if (is_leader_brrip[set] && !hit)
            if (psel < ((1<<PSEL_BITS)-1)) psel++;
    }
    else if (sig_ctr[sig] >= 2) {
        // Signature predicts reusable: insert at MRU
        rrpv[set][way] = 0;
        if (is_leader_srrip[set] && !hit)
            if (psel > 0) psel--;
    }
    else if (sig_ctr[sig] == 0) {
        // Signature predicts dead: insert at LRU
        rrpv[set][way] = 2;
        if (is_leader_brrip[set] && !hit)
            if (psel < ((1<<PSEL_BITS)-1)) psel++;
    }
    else {
        // Uncertain signature: use DIP logic
        if (use_srrip) {
            // SRRIP: insert at distant (2)
            rrpv[set][way] = 2;
        } else {
            // BRRIP: insert at distant (2) 31/32, MRU (0) 1/32
            if ((PC ^ paddr) & 0x1F)
                rrpv[set][way] = 2;
            else
                rrpv[set][way] = 0;
        }
    }
}

void PrintStats() {
    int sig2 = 0, sig3 = 0;
    for (uint32_t i = 0; i < SIG_ENTRIES; ++i) {
        if (sig_ctr[i] == 2) sig2++;
        if (sig_ctr[i] == 3) sig3++;
    }
    std::cout << "SLSH: sig_ctr==2: " << sig2 << " / " << SIG_ENTRIES << std::endl;
    std::cout << "SLSH: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SLSH: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
    std::cout << "SLSH: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int sig3 = 0;
    for (uint32_t i = 0; i < SIG_ENTRIES; ++i)
        if (sig_ctr[i] == 3) sig3++;
    std::cout << "SLSH: sig_ctr==3: " << sig3 << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= STREAM_DETECT_THRESH)
            stream_sets++;
    std::cout << "SLSH: Streaming sets: " << stream_sets << std::endl;
    std::cout << "SLSH: PSEL: " << psel << std::endl;
}