#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV per line ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DRRIP set-dueling: 64 leader sets for SRRIP, 64 for BRRIP ---
#define NUM_LEADER_SETS 64
static uint16_t psel = 512; // 10-bit PSEL, initialized to midpoint

// --- Streaming detector: per-set, last address/delta, 2-bit streaming counter ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Set-dueling leader set selection ---
inline bool IsSRRIPLeader(uint32_t set) { return (set % 512) < NUM_LEADER_SETS; }
inline bool IsBRRIPLeader(uint32_t set) { return (set % 512) >= 512-NUM_LEADER_SETS; }

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    psel = 512;
}

// --- Streaming detector update ---
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    bool streaming = false;
    if (last_delta[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) ++stream_ctr[set];
    } else {
        if (stream_ctr[set] > 0) --stream_ctr[set];
    }
    streaming = (stream_ctr[set] >= 2);
    last_delta[set] = delta;
    last_addr[set] = paddr;
    return streaming;
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
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
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
    bool streaming = IsStreaming(set, paddr);

    // --- DRRIP set-dueling: update PSEL on leader sets ---
    if (IsSRRIPLeader(set)) {
        if (hit && psel < 1023) ++psel;
        else if (!hit && psel > 0) --psel;
    } else if (IsBRRIPLeader(set)) {
        if (!hit && psel < 1023) ++psel;
        else if (hit && psel > 0) --psel;
    }

    // --- On hit: promote to MRU ---
    if (hit) {
        rrpv[set][way] = 0;
        return;
    }

    // --- Streaming detected: bypass fill ---
    if (streaming) {
        rrpv[set][way] = 3; // Insert at distant RRPV (effectively bypass)
        return;
    }

    // --- DRRIP insertion: select SRRIP or BRRIP ---
    bool use_brrip = false;
    if (IsSRRIPLeader(set)) use_brrip = false;
    else if (IsBRRIPLeader(set)) use_brrip = true;
    else use_brrip = (psel < 512); // If psel is low, favor BRRIP

    if (use_brrip) {
        // BRRIP: Insert at RRPV=2 with 1/32 probability, else RRPV=3
        if ((rand() & 31) == 0) rrpv[set][way] = 2;
        else rrpv[set][way] = 3;
    } else {
        // SRRIP: Insert at RRPV=2
        rrpv[set][way] = 2;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DRRIP-SD Policy: DRRIP + Streaming Bypass with Set-Dueling\n";
    std::cout << "PSEL value: " << psel << std::endl;
    // Optionally print streaming counters histogram
    uint32_t stream_hist[4] = {0,0,0,0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        stream_hist[stream_ctr[s]]++;
    std::cout << "Streaming counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}