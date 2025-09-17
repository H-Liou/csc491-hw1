#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits/line
uint16_t psel = 512;                   // 10 bits: DRRIP selector
bool leader_set[LLC_SETS];             // 64 leader sets (true: SRRIP, false: BRRIP)
#define NUM_LEADER_SETS 64

// --- Streaming detector: per-set last addr, stride, score ---
uint64_t last_addr[LLC_SETS];
int8_t last_stride[LLC_SETS];
uint8_t stream_score[LLC_SETS];        // 2 bits/set

// --- Helper: leader set selection ---
inline bool is_leader_set(uint32_t set) {
    // Use first 32 sets as SRRIP leaders, next 32 as BRRIP leaders
    if (set < 32) return true;         // SRRIP leader
    if (set >= 32 && set < 64) return false; // BRRIP leader
    return false;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    psel = 512;
    memset(leader_set, 0, sizeof(leader_set));
    for (uint32_t s = 0; s < 32; ++s) leader_set[s] = true;       // SRRIP leaders
    for (uint32_t s = 32; s < 64; ++s) leader_set[s] = false;     // BRRIP leaders
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_stride, 0, sizeof(last_stride));
    memset(stream_score, 0, sizeof(stream_score));
}

// --- Victim selection: SRRIP ---
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
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
    }
}

// --- Replacement state update ---
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
    int8_t stride = 0;
    if (last_addr[set] != 0)
        stride = (int8_t)((paddr >> 6) - (last_addr[set] >> 6));
    last_addr[set] = paddr;

    // Update stream_score: if stride matches last_stride and nonzero, increment; else reset
    if (stride == last_stride[set] && stride != 0) {
        if (stream_score[set] < 3) stream_score[set]++;
    } else {
        stream_score[set] = 0;
        last_stride[set] = stride;
    }

    bool is_streaming = (stream_score[set] >= 2);

    // --- DRRIP insertion depth ---
    // Determine insertion policy: SRRIP or BRRIP
    bool use_srrip = false;
    if (is_leader_set(set)) {
        use_srrip = leader_set[set];
    } else {
        use_srrip = (psel >= 512);
    }

    // --- Streaming bypass logic ---
    if (!hit) {
        if (is_streaming) {
            // Streaming detected: bypass (do not cache)
            rrpv[set][way] = 3; // Insert at LRU, will be evicted quickly
        } else {
            // Non-streaming: DRRIP insertion
            if (use_srrip) {
                rrpv[set][way] = 2; // SRRIP: insert at distant
            } else {
                rrpv[set][way] = (rand() % 32 == 0) ? 2 : 3; // BRRIP: mostly LRU, rare distant
            }
        }
    } else {
        // On hit: promote to MRU
        rrpv[set][way] = 0;
    }

    // --- DRRIP set-dueling update ---
    if (is_leader_set(set)) {
        // Leader sets: update PSEL
        if (leader_set[set]) {
            // SRRIP leader: increment PSEL on hit
            if (hit && psel < 1023) psel++;
        } else {
            // BRRIP leader: decrement PSEL on hit
            if (hit && psel > 0) psel--;
        }
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "HDSB: DRRIP PSEL value: " << psel << std::endl;
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "HDSB: Streaming sets: " << streaming_sets << std::endl;
}