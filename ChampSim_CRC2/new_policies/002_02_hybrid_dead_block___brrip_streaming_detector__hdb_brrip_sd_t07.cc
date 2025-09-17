#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata ---
// 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Dead-block predictor: 2 bits per block, decay every N fills
uint8_t dead_counter[LLC_SETS][LLC_WAYS];
uint32_t fill_count = 0;

// Streaming detector: 2-bit stride conf, 8-bit last_addr, 8-bit last_delta per set
uint8_t stream_conf[LLC_SETS];
uint64_t stream_last_addr[LLC_SETS];
int16_t stream_last_delta[LLC_SETS];

// BRRIP set-dueling: 32 leader sets for BRRIP, 32 for SRRIP
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10 bits
bool is_leader_brrip[LLC_SETS];
bool is_leader_srrip[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_counter, 1, sizeof(dead_counter));
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(stream_last_addr, 0, sizeof(stream_last_addr));
    memset(stream_last_delta, 0, sizeof(stream_last_delta));
    fill_count = 0;

    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_brrip[s] = true, is_leader_srrip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_brrip[s] = false, is_leader_srrip[s] = true;
        else
            is_leader_brrip[s] = false, is_leader_srrip[s] = false;
    }
}

// --- Streaming detector ---
inline bool detect_streaming(uint32_t set, uint64_t paddr) {
    int16_t delta = (int16_t)(paddr - stream_last_addr[set]);
    bool monotonic = (delta == stream_last_delta[set]) && (delta != 0);

    if (monotonic) {
        if (stream_conf[set] < 3) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    stream_last_delta[set] = delta;
    stream_last_addr[set] = paddr;

    // Streaming if confidence high
    return (stream_conf[set] >= 2);
}

// --- Find victim: RRIP ---
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
    // --- Streaming detector ---
    bool is_streaming = detect_streaming(set, paddr);

    // --- Dead-block update ---
    if (hit) {
        // On hit, increment dead counter (max 3), set RRPV to 0
        if (dead_counter[set][way] < 3) dead_counter[set][way]++;
        rrpv[set][way] = 0;
        // BRRIP set-dueling PSEL update
        if (is_leader_brrip[set]) { if (PSEL < 1023) PSEL++; }
        else if (is_leader_srrip[set]) { if (PSEL > 0) PSEL--; }
        return;
    }

    // --- Periodic decay of dead counters ---
    fill_count++;
    if ((fill_count & 0x1FF) == 0) { // Every 512 fills
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_counter[s][w] > 0) dead_counter[s][w]--;
    }

    // --- Decide insertion policy ---
    uint8_t ins_rrpv = 2; // SRRIP default (mid distant)
    bool use_brrip = false;
    if (is_leader_brrip[set])
        use_brrip = true;
    else if (is_leader_srrip[set])
        use_brrip = false;
    else
        use_brrip = (PSEL < 512);

    // --- Streaming: always insert at distant (or bypass) ---
    if (is_streaming)
        ins_rrpv = 3;
    else if (dead_counter[set][way] <= 1)
        ins_rrpv = 3; // predicted dead: distant
    else
        ins_rrpv = use_brrip ? ((rand() % 32) == 0 ? 2 : 3) : 2; // BRRIP: mostly distant, rare mid; SRRIP: mid

    rrpv[set][way] = ins_rrpv;

    // --- On fill, reset dead counter to 1 (weakly dead) ---
    dead_counter[set][way] = 1;
}

// --- Print stats ---
void PrintStats() {
    std::cout << "Hybrid Dead-Block + BRRIP Streaming Detector: Final statistics." << std::endl;
    std::cout << "PSEL = " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    // Optional: print histogram of dead counters, streaming confidence, PSEL
}