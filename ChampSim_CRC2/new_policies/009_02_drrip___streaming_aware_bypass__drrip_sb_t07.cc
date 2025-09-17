#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line
static uint16_t PSEL; // 10 bits
static bool leader_set[LLC_SETS]; // Mark leader sets (SRRIP/BRRIP)

// --- Streaming detector metadata ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Set-dueling configuration ---
#define NUM_LEADER_SETS 64
#define SRRIP_LEADER_SETS 32
#define BRRIP_LEADER_SETS 32
#define PSEL_MAX 1023
#define PSEL_INIT 512

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    PSEL = PSEL_INIT;
    memset(leader_set, 0, sizeof(leader_set));

    // Assign first SRRIP_LEADER_SETS as SRRIP leaders, next BRRIP_LEADER_SETS as BRRIP
    for (uint32_t i = 0; i < SRRIP_LEADER_SETS; ++i)
        leader_set[i] = true; // SRRIP leader
    for (uint32_t i = SRRIP_LEADER_SETS; i < SRRIP_LEADER_SETS + BRRIP_LEADER_SETS; ++i)
        leader_set[i] = false; // BRRIP leader
    // Other sets are follower sets
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

// --- Victim selection (SRRIP method) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
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

    // --- On hit: promote to MRU ---
    if (hit) {
        rrpv[set][way] = 0;
        return;
    }

    // --- DRRIP insertion: select insertion policy ---
    bool is_leader = (set < SRRIP_LEADER_SETS) || 
                     (set >= SRRIP_LEADER_SETS && set < SRRIP_LEADER_SETS + BRRIP_LEADER_SETS);
    bool use_srrip = false;
    if (set < SRRIP_LEADER_SETS) // SRRIP leader
        use_srrip = true;
    else if (set >= SRRIP_LEADER_SETS && set < SRRIP_LEADER_SETS + BRRIP_LEADER_SETS) // BRRIP leader
        use_srrip = false;
    else // follower set: use PSEL
        use_srrip = (PSEL >= PSEL_MAX / 2);

    // --- Streaming-aware bypass ---
    if (streaming) {
        rrpv[set][way] = 3; // insert at distant RRPV (bypass)
        return;
    }

    // --- DRRIP insertion ---
    if (use_srrip) {
        rrpv[set][way] = 2; // SRRIP: insert at RRPV=2
    } else {
        // BRRIP: insert at RRPV=3 with low probability (1/32), otherwise at 2
        static uint32_t fill_count = 0;
        fill_count++;
        if ((fill_count & 0x1F) == 0) // every 32 fills
            rrpv[set][way] = 3;
        else
            rrpv[set][way] = 2;
    }

    // --- Adjust PSEL on leader sets ---
    if (set < SRRIP_LEADER_SETS) { // SRRIP leader: increment on hit, decrement on miss
        if (hit && PSEL < PSEL_MAX) PSEL++;
        else if (!hit && PSEL > 0) PSEL--;
    }
    else if (set >= SRRIP_LEADER_SETS && set < SRRIP_LEADER_SETS + BRRIP_LEADER_SETS) { // BRRIP leader: decrement on hit, increment on miss
        if (hit && PSEL > 0) PSEL--;
        else if (!hit && PSEL < PSEL_MAX) PSEL++;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DRRIP-SB Policy: Dynamic RRIP + Streaming-Aware Bypass\n";
    std::cout << "PSEL value: " << PSEL << " (SRRIP preference if >= " << (PSEL_MAX / 2) << ")\n";
    // Print histogram of streaming counters
    uint32_t stream_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        stream_hist[stream_ctr[i]]++;
    std::cout << "Streaming counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}