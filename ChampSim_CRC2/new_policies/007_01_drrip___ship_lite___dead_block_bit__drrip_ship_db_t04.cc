#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits/line
uint8_t dead_bit[LLC_SETS][LLC_WAYS];    // 1 bit/line

// --- SHiP-lite: Per-set signature table ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 per set
uint8_t ship_sig[LLC_SETS][SHIP_SIG_ENTRIES]; // 2 bits per signature

// --- DRRIP set-dueling ---
#define PSEL_BITS 10
uint16_t psel; // 10 bits
#define NUM_LEADER_SETS 32
#define SRRIP_LEADER_SETS 16
#define BRRIP_LEADER_SETS 16

bool IsSRRIPLeaderSet(uint32_t set) { return set < SRRIP_LEADER_SETS; }
bool IsBRRIPLeaderSet(uint32_t set) { return set >= SRRIP_LEADER_SETS && set < (SRRIP_LEADER_SETS + BRRIP_LEADER_SETS); }

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(dead_bit, 0, sizeof(dead_bit));
    memset(ship_sig, 1, sizeof(ship_sig)); // Neutral SHiP counters
    psel = (1 << (PSEL_BITS - 1)); // midpoint
}

// --- Victim selection: Dead-block first, then SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks for eviction
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_bit[set][way])
            return way;

    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
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
    // --- SHiP signature: 6 bits from PC ---
    uint32_t sig = (PC ^ (PC >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- DRRIP insertion policy: set-dueling ---
    bool use_brrip = false;
    if (IsSRRIPLeaderSet(set))
        use_brrip = false;
    else if (IsBRRIPLeaderSet(set))
        use_brrip = true;
    else
        use_brrip = (psel < (1 << (PSEL_BITS - 1)));

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // Promote to MRU
        dead_bit[set][way] = 0; // Mark as live
        if (ship_sig[set][sig] < 3) ship_sig[set][sig]++;
        // PSEL increment for SRRIP leader sets
        if (IsSRRIPLeaderSet(set) && psel < ((1 << PSEL_BITS) - 1)) psel++;
        // PSEL decrement for BRRIP leader sets
        if (IsBRRIPLeaderSet(set) && psel > 0) psel--;
    } else {
        // On fill: SHiP-guided insertion depth
        if (ship_sig[set][sig] >= 2) {
            // Frequent reuse: insert at MRU
            rrpv[set][way] = 0;
        } else if (use_brrip) {
            // BRRIP: insert at distant RRPV (3) with low probability
            rrpv[set][way] = (rand() % 32 == 0) ? 2 : 3;
        } else {
            // SRRIP: insert at RRPV=2
            rrpv[set][way] = 2;
        }
        dead_bit[set][way] = 1; // Mark as dead on fill
        if (ship_sig[set][sig] > 0) ship_sig[set][sig]--; // Weakly not reused
    }
}

// --- Stats ---
void PrintStats() {
    int ship_reused = 0, ship_total = 0, dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
            if (ship_sig[s][i] >= 2) ship_reused++;
            ship_total++;
        }
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_bit[s][w]) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "DRRIP-SHiP-DB: SHiP reused sigs: " << ship_reused << " / " << ship_total << std::endl;
    std::cout << "DRRIP-SHiP-DB: Dead blocks: " << dead_blocks << " / " << total_blocks << std::endl;
    std::cout << "DRRIP-SHiP-DB: PSEL value: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_bit[s][w]) dead_blocks++;
    std::cout << "DRRIP-SHiP-DB: Dead blocks: " << dead_blocks << std::endl;
}