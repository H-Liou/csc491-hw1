#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit signature table (indexed by PC CRC), 2-bit outcome counters
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_ctr[SHIP_TABLE_SIZE]; // 2 bits per entry

// Per-line: store 6-bit signature for update on victim
uint8_t line_signature[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set, last address and delta, 2-bit streaming counter
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// Helper: compute 6-bit SHiP signature from PC
inline uint8_t GetSignature(uint64_t PC) {
    return (champsim_crc2(PC, 0xdeadbeef) & (SHIP_TABLE_SIZE-1));
}

// Initialize replacement state
void InitReplacementState() {
    memset(ship_ctr, 1, sizeof(ship_ctr)); // neutral initial value
    memset(line_signature, 0, sizeof(line_signature));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
}

// Streaming detector (called on every access/fill)
void UpdateStreamingDetector(uint32_t set, uint64_t paddr) {
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
}

// Find victim in the set
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
    // Standard RRIP victim search (fixed 2-bit per block)
    static uint8_t rrpv[LLC_SETS][LLC_WAYS] = {{0}};
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
}

// Update replacement state
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
    UpdateStreamingDetector(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);

    // --- Per-block RRIP storage (static, since C++ can't keep per-block state inside function) ---
    static uint8_t rrpv[LLC_SETS][LLC_WAYS] = {{0}};

    // --- On hit: promote to MRU, update SHiP outcome counter ---
    if (hit) {
        rrpv[set][way] = 0;
        // Positive reuse: saturate up SHiP counter
        if (ship_ctr[sig] < 3) ship_ctr[sig]++;
        return;
    }

    // --- On miss/fill: record victim line's signature for SHiP learning ---
    uint8_t victim_sig = line_signature[set][way];
    if (victim_sig) {
        // No reuse: decrement outcome counter
        if (ship_ctr[victim_sig] > 0) ship_ctr[victim_sig]--;
    }
    line_signature[set][way] = sig;

    // --- Insertion depth: combine streaming detector and SHiP ---
    uint8_t ins_rrpv = 2; // default SRRIP insertion

    if (stream_ctr[set] >= 2) {
        // Streaming detected: bypass aggressively
        ins_rrpv = 3;
    } else {
        // SHiP: if signature has low reuse, insert at distant RRPV
        if (ship_ctr[sig] <= 1)
            ins_rrpv = 3; // Dead block: distant insertion
        else
            ins_rrpv = 2; // Potential reuse: normal insertion
    }
    rrpv[set][way] = ins_rrpv;
}

// Print end-of-simulation statistics
void PrintStats() {
    // SHiP counter histogram
    uint64_t ship_hist[4] = {0};
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        ship_hist[ship_ctr[i]]++;
    std::cout << "SHiP-ASB: SHiP counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << ship_hist[i] << " ";
    std::cout << std::endl;

    // Streaming counter histogram
    uint64_t stream_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        stream_hist[stream_ctr[s]]++;
    std::cout << "SHiP-ASB: Streaming counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age streaming counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] > 0)
            stream_ctr[s]--;
    // Periodically decay SHiP counters to adapt to phase changes
    static int tick = 0;
    if (++tick % 4096 == 0) {
        for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
            if (ship_ctr[i] > 1) ship_ctr[i]--;
    }
}