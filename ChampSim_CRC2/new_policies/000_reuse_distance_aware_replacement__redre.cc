#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include <cassert>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Tunable Parameters ---
static const int PC_TABLE_SIZE     = 4096;   // entries in PC reuse table
static const int REUSE_MAX         = 31;     // max counter value
static const int REUSE_HIGH_THRES  = 20;     // >= high reuse
static const int REUSE_LOW_THRES   = 10;     // < low reuse

// --- Replacement State Structures ---
struct BlockInfo {
    uint8_t  priority;    // 0 = low, 1 = mid, 2 = high
    uint64_t last_access; // timestamp for true LRU tie-break
};

static BlockInfo ReplState[LLC_SETS][LLC_WAYS];

// PC Reuse Table Entry
struct PCTableEntry {
    uint64_t pc;
    uint8_t  counter;   // [0..REUSE_MAX]
    bool     valid;
};

static PCTableEntry PCTable[PC_TABLE_SIZE];
static uint64_t global_timestamp = 0;

// --- Statistics ---
static uint64_t stat_hits       = 0;
static uint64_t stat_misses     = 0;
static uint64_t stat_inserts[3] = {0,0,0}; // count of low/mid/high inserts

// ---- Hash function for PC table ----
static inline uint32_t pc_hash(uint64_t pc) {
    // simple XOR-fold and modulo
    return (uint32_t)((pc ^ (pc >> 16)) & (PC_TABLE_SIZE - 1));
}

// Initialize replacement state
void InitReplacementState() {
    // Clear block info
    for (int s = 0; s < LLC_SETS; s++) {
        for (int w = 0; w < LLC_WAYS; w++) {
            ReplState[s][w].priority    = 1;     // start as medium
            ReplState[s][w].last_access = 0;
        }
    }
    // Clear PC table
    for (int i = 0; i < PC_TABLE_SIZE; i++) {
        PCTable[i].valid   = false;
        PCTable[i].pc      = 0;
        PCTable[i].counter = REUSE_LOW_THRES; // neutral
    }
    global_timestamp = 1;
}

// Lookup or install PC entry, return index
static uint32_t LookupPCEntry(uint64_t PC) {
    uint32_t idx = pc_hash(PC);
    // linear probe
    for (int i = 0; i < 8; i++) {
        uint32_t j = (idx + i) & (PC_TABLE_SIZE - 1);
        if (!PCTable[j].valid) {
            // install
            PCTable[j].valid   = true;
            PCTable[j].pc      = PC;
            PCTable[j].counter = REUSE_LOW_THRES;
            return j;
        }
        if (PCTable[j].pc == PC) {
            return j;
        }
    }
    // fallback: override idx
    PCTable[idx].pc      = PC;
    PCTable[idx].counter = REUSE_LOW_THRES;
    return idx;
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
    // Choose the way with lowest priority; tie-break by oldest last_access
    uint8_t  best_prio = 3;    // higher than any real prio
    uint64_t worst_ts  = UINT64_MAX;
    uint32_t victim    = 0;

    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        uint8_t pr = ReplState[set][w].priority;
        uint64_t ts= ReplState[set][w].last_access;
        if (pr < best_prio || (pr == best_prio && ts < worst_ts)) {
            best_prio = pr;
            worst_ts  = ts;
            victim    = w;
        }
    }
    return victim;
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
    // Advance timestamp
    global_timestamp++;

    // Update PC reuse table
    uint32_t entry = LookupPCEntry(PC);
    if (hit) {
        stat_hits++;
        if (PCTable[entry].counter < REUSE_MAX) PCTable[entry].counter++;
    } else {
        stat_misses++;
        if (PCTable[entry].counter > 0)            PCTable[entry].counter--;
    }

    if (hit) {
        // On a hit, refresh recency
        ReplState[set][way].last_access = global_timestamp;
        // Optionally bump priority on hit
        if (PCTable[entry].counter >= REUSE_HIGH_THRES)
            ReplState[set][way].priority = 2;
        else if (PCTable[entry].counter < REUSE_LOW_THRES)
            ReplState[set][way].priority = 0;
        else
            ReplState[set][way].priority = 1;
    } else {
        // On a miss, we have just installed a new block at [set][way]
        uint8_t prio;
        if (PCTable[entry].counter >= REUSE_HIGH_THRES)      prio = 2;
        else if (PCTable[entry].counter < REUSE_LOW_THRES)   prio = 0;
        else                                                 prio = 1;
        ReplState[set][way].priority    = prio;
        ReplState[set][way].last_access = global_timestamp;
        stat_inserts[prio]++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint64_t total = stat_hits + stat_misses;
    double hit_rate = total ? (100.0 * stat_hits / total) : 0.0;
    std::cout << "---- ReDRe Replacement Stats ----\n";
    std::cout << "Total Accesses: " << total << "\n";
    std::cout << "Hits:           " << stat_hits
              << "  Misses: " << stat_misses
              << "  Hit Rate: " << hit_rate << "%\n";
    std::cout << "Insert Counts: Low=" << stat_inserts[0]
              << " Mid=" << stat_inserts[1]
              << " High=" << stat_inserts[2] << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}