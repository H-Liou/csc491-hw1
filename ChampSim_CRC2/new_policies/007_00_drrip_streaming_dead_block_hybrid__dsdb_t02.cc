#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DRRIP set-dueling: leader sets and PSEL ---
#define NUM_LEADER_SETS 32
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];
uint16_t psel; // 10 bits

// --- Streaming detector: per-set, 2-entry delta history, 2-bit streaming counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Dead-block counter: 2 bits per line ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(dead_ctr, 0, sizeof(dead_ctr));

    // Assign leader sets for DRRIP set-dueling
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS - 1 - i] = 1;
    }
    psel = 512; // midpoint for 10 bits
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

// --- DRRIP insertion depth selection ---
inline uint8_t GetDRRIP_InsertRRPV(uint32_t set) {
    // Leader sets: always SRRIP or BRRIP
    if (is_srrip_leader[set]) return 2; // SRRIP: insert at RRPV=2
    if (is_brrip_leader[set]) return (rand() % 32 == 0) ? 2 : 3; // BRRIP: mostly RRPV=3, rare RRPV=2
    // Follower sets: use PSEL
    return (psel >= 512) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
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

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        dead_ctr[set][way] = 0; // reset dead-block counter on reuse
        return;
    }

    // --- Dead-block prediction ---
    bool predicted_dead = (dead_ctr[set][way] == 3);

    // --- DRRIP insertion depth ---
    uint8_t drrip_rrpv = GetDRRIP_InsertRRPV(set);

    // --- Streaming: bypass or distant insertion ---
    if (streaming) {
        rrpv[set][way] = 3; // insert at distant RRPV
        return;
    }

    // --- Dead-block: insert at distant RRPV if predicted dead ---
    if (predicted_dead) {
        rrpv[set][way] = 3;
        return;
    }

    // --- Otherwise, DRRIP advice ---
    rrpv[set][way] = drrip_rrpv;
}

// --- On eviction: update dead-block counter and DRRIP PSEL ---
void OnEviction(
    uint32_t set, uint32_t way, bool was_hit
) {
    // Dead-block: increment if not reused (evicted at RRPV==3)
    if (!was_hit && rrpv[set][way] == 3) {
        if (dead_ctr[set][way] < 3) ++dead_ctr[set][way];
    }

    // DRRIP set-dueling: update PSEL for leader sets
    if (is_srrip_leader[set]) {
        if (was_hit) { if (psel < 1023) ++psel; }
        else { if (psel > 0) --psel; }
    }
    if (is_brrip_leader[set]) {
        if (was_hit) { if (psel > 0) --psel; }
        else { if (psel < 1023) ++psel; }
    }
}

// --- Periodic decay of dead-block counters ---
void DecayMetadata() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] > 0) --dead_ctr[set][way];
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DSDB Policy: DRRIP + Streaming Detector + Dead-block Hybrid\n";
    std::cout << "PSEL value: " << psel << "\n";
}
void PrintStats_Heartbeat() {}