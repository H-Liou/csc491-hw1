#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV per line ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- DRRIP: Set-dueling leader sets and PSEL ---
#define NUM_LEADER_SETS 32
uint8_t is_sr_leader[LLC_SETS]; // 1 if SRRIP leader, 2 if BRRIP leader, 0 otherwise
uint16_t psel = 512; // 10-bit PSEL, initialized to midpoint

// --- Streaming detector: per-set, 2-entry delta history, 2-bit streaming counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(is_sr_leader, 0, sizeof(is_sr_leader));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    psel = 512;

    // Assign leader sets: first NUM_LEADER_SETS/2 are SRRIP, next NUM_LEADER_SETS/2 are BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS/2; ++i)
        is_sr_leader[i] = 1;
    for (uint32_t i = NUM_LEADER_SETS/2; i < NUM_LEADER_SETS; ++i)
        is_sr_leader[i] = 2;
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
    // Streaming detected: bypass (return invalid way)
    if (IsStreaming(set, paddr))
        return LLC_WAYS; // signal bypass (no insertion)

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
    // Streaming detected: bypass, do not update state
    if (way == LLC_WAYS)
        return;

    // DRRIP set-dueling: update PSEL on leader sets
    if (is_sr_leader[set] == 1) { // SRRIP leader
        if (hit && psel < 1023) ++psel;
    } else if (is_sr_leader[set] == 2) { // BRRIP leader
        if (hit && psel > 0) --psel;
    }

    // On hit: promote to MRU
    if (hit) {
        rrpv[set][way] = 0;
        return;
    }

    // On fill: choose insertion policy
    bool use_brrip = false;
    if (is_sr_leader[set] == 1)
        use_brrip = false; // SRRIP leader: always SRRIP
    else if (is_sr_leader[set] == 2)
        use_brrip = true;  // BRRIP leader: always BRRIP
    else
        use_brrip = (psel < 512); // follower sets: select by PSEL

    // BRRIP: insert at RRPV=2 with probability 31/32, else RRPV=0
    if (use_brrip) {
        if ((rand() & 31) != 0)
            rrpv[set][way] = 2;
        else
            rrpv[set][way] = 0;
    } else {
        rrpv[set][way] = 2; // SRRIP: insert at RRPV=2
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DRRIP-SB Policy: DRRIP + Streaming Bypass\n";
    std::cout << "Final PSEL value: " << psel << std::endl;
    // Streaming histogram
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2) streaming_sets++;
    std::cout << "Sets streaming at end: " << streaming_sets << "/" << LLC_SETS << std::endl;
}
void PrintStats_Heartbeat() {}