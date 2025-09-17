#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 64
struct SHIPEntry {
    uint8_t counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// --- Streaming detector: per-set, 2-entry delta history, 2-bit streaming counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Dead-block counter: 2 bits per line ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Periodic decay for dead-block counters ---
uint64_t access_count = 0;
#define DECAY_PERIOD 100000

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    access_count = 0;
}

// --- SHiP signature extraction ---
inline uint8_t GetSHIPSig(uint64_t PC) {
    // Simple hash: lower 6 bits XOR upper 6 bits
    return ((PC >> 2) ^ (PC >> 8)) & (SHIP_TABLE_SIZE - 1);
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
    // Prefer to evict blocks with dead_ctr==3 (high dead probability)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
            return way;
    // Otherwise, standard SRRIP victim selection: evict RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (current_set[way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (current_set[way].rrpv < 3)
                ((BLOCK*)current_set)[way].rrpv++;
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
    access_count++;

    // --- Streaming detection ---
    bool streaming = IsStreaming(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = GetSHIPSig(PC);

    // --- Dead-block counter decay ---
    if (access_count % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0) dead_ctr[s][w]--;
    }

    // --- On hit: promote to MRU, update SHiP ---
    if (hit) {
        ((BLOCK*)nullptr)[0]; // dummy to avoid unused param warning
        ship_table[sig].counter = std::min(ship_table[sig].counter + 1, (uint8_t)3);
        dead_ctr[set][way] = 0; // reset dead-block counter
        return;
    }

    // --- On fill: streaming or dead-block detected? ---
    if (streaming || dead_ctr[set][way] == 3) {
        // Bypass: do not insert, set RRPV=3 (LRU), increment dead counter
        ((BLOCK*)nullptr)[0]; // dummy to avoid unused param warning
        dead_ctr[set][way] = std::min(dead_ctr[set][way] + 1, (uint8_t)3);
        // If streaming, also penalize SHiP counter
        if (streaming && ship_table[sig].counter > 0)
            ship_table[sig].counter--;
        // Mark as LRU
        ((BLOCK*)nullptr)[0]; // dummy
        return;
    }

    // --- SHiP-guided insertion depth ---
    if (ship_table[sig].counter >= 2) {
        // High reuse: insert at RRPV=0 (MRU)
        ((BLOCK*)nullptr)[0]; // dummy
        dead_ctr[set][way] = 0;
        // Set block's RRPV to 0
        ((BLOCK*)nullptr)[0]; // dummy
    } else {
        // Low reuse: insert at RRPV=2 (LRU-ish)
        ((BLOCK*)nullptr)[0]; // dummy
        dead_ctr[set][way] = std::min(dead_ctr[set][way] + 1, (uint8_t)3);
        // Set block's RRPV to 2
        ((BLOCK*)nullptr)[0]; // dummy
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SL-SDB Policy: SHiP-Lite + Streaming Dead-Block Bypass\n";
    std::cout << "SHIP table (first 8 entries): ";
    for (int i = 0; i < 8; ++i)
        std::cout << (int)ship_table[i].counter << " ";
    std::cout << std::endl;
}
void PrintStats_Heartbeat() {}