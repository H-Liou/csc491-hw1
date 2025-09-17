#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits/line

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_TABLE_SIZE 2048
struct SHIPEntry {
    uint8_t counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// --- Per-line signature ---
uint8_t line_sig[LLC_SETS][LLC_WAYS];    // 6 bits/line

// --- Streaming detector: per-set, 2-bit state + last address ---
uint64_t last_addr[LLC_SETS];
uint8_t stream_state[LLC_SETS]; // 2 bits: 0=unknown, 1=monotonic, 2=not streaming

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(ship_table, 0, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_state, 0, sizeof(stream_state));
}

// --- Streaming detection helper ---
inline bool DetectStreaming(uint32_t set, uint64_t paddr) {
    // Streaming: monotonic stride (e.g., +blocksize or -blocksize)
    uint64_t stride = paddr - last_addr[set];
    bool is_stream = false;
    if (last_addr[set] != 0) {
        if ((stride == 64) || (stride == -64)) { // 64B block
            if (stream_state[set] < 2) stream_state[set]++;
            if (stream_state[set] >= 2) is_stream = true;
        } else {
            if (stream_state[set] > 0) stream_state[set]--;
        }
    }
    last_addr[set] = paddr;
    return is_stream;
}

// --- Victim selection: standard SRRIP ---
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
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
    }
}

// --- Replacement state update ---
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
    // --- SHiP signature ---
    uint16_t sig = champsim_crc2(PC, SHIP_SIG_BITS) & SHIP_SIG_MASK;

    // --- Streaming detection ---
    bool is_stream = DetectStreaming(set, paddr);

    // --- On cache hit ---
    if (hit) {
        // Promote to MRU
        rrpv[set][way] = 0;
        // Update SHiP outcome: increment counter (max 3)
        if (ship_table[sig].counter < 3) ship_table[sig].counter++;
    } else {
        // On fill: choose insertion depth
        if (is_stream) {
            // Streaming: insert at distant RRPV (3), or bypass with probability 1/8
            if ((rand() & 0x7) == 0) {
                // Bypass: do not install block (simulate by setting RRPV=3, never promote)
                rrpv[set][way] = 3;
            } else {
                rrpv[set][way] = 3;
            }
        } else {
            // SHiP: use signature outcome to bias insertion
            if (ship_table[sig].counter >= 2) {
                // Frequent reuse: insert at MRU
                rrpv[set][way] = 0;
            } else {
                // Infrequent: insert at RRPV=2
                rrpv[set][way] = 2;
            }
        }
        // Save signature in line metadata
        line_sig[set][way] = sig;
    }

    // --- On eviction: update SHiP outcome ---
    if (!hit && victim_addr) {
        uint8_t victim_sig = line_sig[set][way];
        // If block was not reused, decrement counter (min 0)
        if (ship_table[victim_sig].counter > 0) ship_table[victim_sig].counter--;
    }
}

// --- Stats ---
void PrintStats() {
    int reused = 0, inserted = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_table[i].counter > 1) reused++;
        inserted++;
    }
    std::cout << "SHiP-SB: High-reuse signatures: " << reused << " / " << inserted << std::endl;
}

void PrintStats_Heartbeat() {
    int reused = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].counter > 1) reused++;
    std::cout << "SHiP-SB: High-reuse signatures: " << reused << std::endl;
}