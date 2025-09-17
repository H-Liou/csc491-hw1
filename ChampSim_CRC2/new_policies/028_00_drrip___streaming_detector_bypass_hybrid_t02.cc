#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP state: 2 bits per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- DRRIP set-dueling: 64 leader sets, 10-bit PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t psel = PSEL_MAX / 2; // 10-bit PSEL
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower

// --- Streaming detector: per-set history ---
struct StreamHist {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_ctr; // 2 bits: saturating counter
};
StreamHist stream_hist[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(stream_hist, 0, sizeof(stream_hist));
    // Assign leader sets: first 32 SRRIP, next 32 BRRIP, rest followers
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS / 2)
            leader_set_type[s] = 0; // SRRIP leader
        else if (s < NUM_LEADER_SETS)
            leader_set_type[s] = 1; // BRRIP leader
        else
            leader_set_type[s] = 2; // follower
    }
    psel = PSEL_MAX / 2;
}

// --- Streaming detector: returns true if streaming detected ---
inline bool is_streaming(uint32_t set, uint64_t paddr) {
    StreamHist &hist = stream_hist[set];
    int64_t delta = int64_t(paddr) - int64_t(hist.last_addr);
    bool monotonic = (delta == hist.last_delta) && (delta != 0);
    // Update streaming counter
    if (monotonic) {
        if (hist.stream_ctr < 3) hist.stream_ctr++;
    } else {
        if (hist.stream_ctr > 0) hist.stream_ctr--;
    }
    // Update history
    hist.last_delta = delta;
    hist.last_addr = paddr;
    // Streaming detected if counter saturates
    return (hist.stream_ctr >= 2);
}

// --- Find victim: standard RRIP ---
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
    // --- Streaming detection ---
    bool streaming = is_streaming(set, paddr);

    // --- DRRIP insertion policy selection ---
    uint8_t ins_rrpv = 2; // default SRRIP
    if (leader_set_type[set] == 0) {
        // SRRIP leader: always insert at RRPV=2
        ins_rrpv = 2;
    } else if (leader_set_type[set] == 1) {
        // BRRIP leader: insert at RRPV=3 with low probability (1/32)
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3;
    } else {
        // Follower: use PSEL to choose
        if (psel >= PSEL_MAX / 2)
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
    }

    // --- Streaming bypass/insertion depth ---
    if (streaming) {
        // If streaming detected, bypass (do not insert) or insert at RRPV=3
        ins_rrpv = 3;
    }

    // --- On hit: promote block ---
    if (hit) {
        rrpv[set][way] = 0;
    } else {
        rrpv[set][way] = ins_rrpv;
    }

    // --- DRRIP set-dueling update ---
    if (!hit) {
        // Only update PSEL for leader sets
        if (leader_set_type[set] == 0) {
            // SRRIP leader: increment PSEL if miss
            if (psel < PSEL_MAX) psel++;
        } else if (leader_set_type[set] == 1) {
            // BRRIP leader: decrement PSEL if miss
            if (psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Streaming Detector Hybrid: Final statistics." << std::endl;
    std::cout << "PSEL value: " << psel << " (SRRIP if >= " << (PSEL_MAX / 2) << ")" << std::endl;
    // Streaming sets count
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_hist[s].stream_ctr >= 2)
            streaming_sets++;
    std::cout << "Sets detected streaming: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL and streaming set count
}