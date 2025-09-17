#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];           // 2 bits per block

// --- SHiP-lite metadata ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024
uint8_t ship_counter[SHIP_SIG_ENTRIES];     // 2 bits per entry

// --- Streaming detector metadata ---
uint64_t last_addr[LLC_SETS];               // 8 bytes per set
int8_t stream_score[LLC_SETS];              // 1 byte per set

// --- Streaming detector parameters ---
#define STREAM_SCORE_MAX 7
#define STREAM_SCORE_MIN -7
#define STREAM_DETECT_THRESH 5

// --- Helper: get SHiP signature from PC ---
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2)) & ((1 << SHIP_SIG_BITS) - 1);
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_counter, 1, sizeof(ship_counter));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
}

// --- Find victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
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
    uint16_t sig = get_signature(PC);

    // --- Streaming detector ---
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    last_addr[set] = paddr;
    // Detect monotonic stride (positive or negative)
    if (delta == 64 || delta == -64) { // 64B line stride
        if (stream_score[set] < STREAM_SCORE_MAX) stream_score[set]++;
    } else {
        if (stream_score[set] > STREAM_SCORE_MIN) stream_score[set]--;
    }

    // --- On hit: update SHiP ---
    if (hit) {
        if (ship_counter[sig] < 3) ship_counter[sig]++;
        rrpv[set][way] = 0;
        return;
    }

    // --- Choose insertion depth ---
    uint8_t ins_rrpv = 3; // default distant

    // Streaming: bypass or distant insert if detected
    if (stream_score[set] >= STREAM_DETECT_THRESH || stream_score[set] <= -STREAM_DETECT_THRESH) {
        // Optionally bypass: do not insert into cache (simulate by distant insert)
        ins_rrpv = 3;
    } else {
        // SHiP bias: if signature shows reuse, use near insert
        if (ship_counter[sig] >= 2)
            ins_rrpv = 1;
        else
            ins_rrpv = 3;
    }

    // Insert block
    rrpv[set][way] = ins_rrpv;
    // Decay SHiP counter on miss
    if (ship_counter[sig] > 0) ship_counter[sig]--;
}

// --- Stats ---
void PrintStats() {
    std::cout << "SSBA Policy: SHiP-lite + Streaming Detector, adaptive insertion/bypass" << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print streaming detector histogram
}