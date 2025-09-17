#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

// --- Parameters ---
#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

#define SHIP_SIG_BITS 13  // 8K-entry signature table
#define SHIP_SIG_SIZE (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2 // 2-bit per signature

#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define SRRIP_MAX 3

// --- Metadata structures ---
// 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 8K-entry signature table, 2-bit reuse counters
uint8_t ship_sig[SHIP_SIG_SIZE];

// Per-line signatures for tracking
uint16_t line_sig[LLC_SETS][LLC_WAYS];

// DRRIP set-dueling: 32 SRRIP, 32 BRRIP leader sets
uint32_t leader_sets[NUM_LEADER_SETS];
uint16_t PSEL = 512;

// Streaming detector: per-set last address, delta, streaming flag
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 2 bits
    bool is_streaming;
};
StreamDetect stream_detect[LLC_SETS];

// --- Helper functions ---
inline bool IsSRRIPLeader(uint32_t set) {
    for (int i = 0; i < NUM_LEADER_SETS / 2; ++i)
        if (leader_sets[i] == set) return true;
    return false;
}
inline bool IsBRRIPLeader(uint32_t set) {
    for (int i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set) return true;
    return false;
}
inline uint16_t GetSignature(uint64_t PC) {
    // Simple CRC or lower bits as signature
    return champsim_crc2(PC) & (SHIP_SIG_SIZE - 1);
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, SRRIP_MAX, sizeof(rrpv));
    memset(ship_sig, 1, sizeof(ship_sig)); // Weak reuse at start
    memset(line_sig, 0, sizeof(line_sig));
    memset(stream_detect, 0, sizeof(stream_detect));
    // Assign leader sets: evenly spaced
    for (int i = 0; i < NUM_LEADER_SETS; ++i)
        leader_sets[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
    PSEL = 512;
}

// --- Streaming detector ---
bool DetectStreaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_detect[set];
    int64_t delta = paddr - sd.last_addr;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_count < 3) ++sd.stream_count;
        } else {
            if (sd.stream_count > 0) --sd.stream_count;
        }
        sd.is_streaming = (sd.stream_count >= 2);
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return sd.is_streaming;
}

// --- Victim selection (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == SRRIP_MAX)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < SRRIP_MAX) ++rrpv[set][way];
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
    // Streaming detection
    bool streaming = DetectStreaming(set, paddr);

    // Get the block's SHiP signature
    uint16_t sig = GetSignature(PC);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // SHiP: increment reuse counter for this signature
        if (ship_sig[sig] < 3) ++ship_sig[sig];
        // DRRIP set-dueling PSEL update
        if (IsSRRIPLeader(set)) {
            if (PSEL < ((1 << PSEL_BITS) - 1)) ++PSEL;
        } else if (IsBRRIPLeader(set)) {
            if (PSEL > 0) --PSEL;
        }
        return;
    }

    // --- On fill ---
    // Streaming: bypass fill (insert at distant RRPV, mark as dead)
    if (streaming) {
        rrpv[set][way] = SRRIP_MAX;
        line_sig[set][way] = sig;
        // Decrement SHiP reuse counter (dead block)
        if (ship_sig[sig] > 0) --ship_sig[sig];
        return;
    }

    // DRRIP policy selection
    bool use_srrip = false;
    if (IsSRRIPLeader(set)) use_srrip = true;
    else if (IsBRRIPLeader(set)) use_srrip = false;
    else use_srrip = (PSEL >= (1 << (PSEL_BITS - 1)));

    // SHiP insertion depth: if signature shows high reuse, insert at MRU
    if (ship_sig[sig] >= 2) {
        rrpv[set][way] = 0; // MRU
    } else {
        // Adapt insertion depth according to DRRIP
        if (use_srrip) {
            rrpv[set][way] = SRRIP_MAX - 1; // Insert at RRPV=2
        } else {
            // BRRIP: insert at RRPV=2 only 1/32 fills, else RRPV=3
            if ((rand() % 32) == 0)
                rrpv[set][way] = SRRIP_MAX - 1;
            else
                rrpv[set][way] = SRRIP_MAX;
        }
    }
    line_sig[set][way] = sig;
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SDSB Policy: SHiP-lite + DRRIP Set-Dueling + Streaming Bypass\n";
}
void PrintStats_Heartbeat() {}