#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set last address, last delta, 2-bit streaming counter, streaming flag
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 2 bits
    bool is_streaming;
};
StreamDetect stream_detect[LLC_SETS];

// DIP set-dueling: 32 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 32
uint32_t leader_sets[NUM_LEADER_SETS];
uint16_t PSEL = 512; // 10 bits, midpoint

// Helper: assign leader sets (first 16 for LIP, next 16 for BIP)
inline bool IsLIPLeader(uint32_t set) {
    for (int i = 0; i < NUM_LEADER_SETS / 2; ++i)
        if (leader_sets[i] == set) return true;
    return false;
}
inline bool IsBIPLeader(uint32_t set) {
    for (int i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set) return true;
    return false;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max (LRU)
    memset(stream_detect, 0, sizeof(stream_detect));
    // Assign leader sets: evenly spaced
    for (int i = 0; i < NUM_LEADER_SETS; ++i)
        leader_sets[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
    PSEL = 512;
}

// --- Streaming detector ---
// Returns true if streaming detected for this set
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

// --- Victim selection ---
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
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
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
    bool streaming = DetectStreaming(set, paddr);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Update PSEL for leader sets
        if (IsLIPLeader(set)) {
            if (PSEL < 1023) ++PSEL;
        } else if (IsBIPLeader(set)) {
            if (PSEL > 0) --PSEL;
        }
        return;
    }

    // --- On fill ---
    if (streaming) {
        // Streaming: bypass fill (do not insert into cache)
        rrpv[set][way] = 3; // Insert at LRU, immediate victim
        return;
    }

    // DIP-style insertion: choose between LIP and BIP
    bool use_lip = false;
    if (IsLIPLeader(set)) use_lip = true;
    else if (IsBIPLeader(set)) use_lip = false;
    else use_lip = (PSEL >= 512);

    if (use_lip) {
        // LIP: always insert at LRU (RRPV=3)
        rrpv[set][way] = 3;
    } else {
        // BIP: insert at LRU (RRPV=3) most of the time, MRU (RRPV=0) 1/32 times
        if ((rand() % 32) == 0)
            rrpv[set][way] = 0;
        else
            rrpv[set][way] = 3;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "ASLH Policy: Adaptive Streaming-LIP Hybrid (Streaming bypass + DIP LIP/BIP set-dueling)\n";
}
void PrintStats_Heartbeat() {}