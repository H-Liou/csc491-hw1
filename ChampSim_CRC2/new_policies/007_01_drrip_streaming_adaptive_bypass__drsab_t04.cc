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

// --- DRRIP set-dueling: 10-bit PSEL ---
uint16_t PSEL = 512; // 10 bits, midpoint 512

// --- DRRIP leader sets ---
#define NUM_LEADER_SETS 64
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];

// --- Streaming detector: per-set, 2-entry delta history, 2-bit streaming counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    // Assign leader sets: evenly distribute
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS - 1 - i] = 1;
    }
    PSEL = 512;
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

    // --- DRRIP insertion policy selection ---
    bool use_brrip = false;
    if (is_srrip_leader[set])
        use_brrip = false;
    else if (is_brrip_leader[set])
        use_brrip = true;
    else
        use_brrip = (PSEL < 512);

    // --- On hit: promote to MRU ---
    if (hit) {
        rrpv[set][way] = 0;
        return;
    }

    // --- Streaming detected: bypass or insert at distant RRPV ---
    if (streaming) {
        // Bypass: do not insert, mark block as "invalid" (max RRPV)
        rrpv[set][way] = 3;
        return;
    }

    // --- On fill: DRRIP insertion ---
    if (use_brrip) {
        // BRRIP: insert at RRPV=2 (long re-reference interval)
        rrpv[set][way] = 2;
    } else {
        // SRRIP: insert at RRPV=1 (medium re-reference interval)
        rrpv[set][way] = 1;
    }
}

// --- On eviction: update PSEL for DRRIP set-dueling ---
void OnEviction(
    uint32_t set, uint32_t way, uint8_t hit
) {
    // Only update on leader sets
    if (is_srrip_leader[set]) {
        if (hit && PSEL < 1023) ++PSEL;
        else if (!hit && PSEL > 0) --PSEL;
    } else if (is_brrip_leader[set]) {
        if (hit && PSEL > 0) --PSEL;
        else if (!hit && PSEL < 1023) ++PSEL;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DRSAB Policy: DRRIP + Streaming Adaptive Bypass\n";
    std::cout << "Final PSEL value: " << PSEL << std::endl;
}
void PrintStats_Heartbeat() {}