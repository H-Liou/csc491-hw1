#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRIP_MAX 3
#define RRIP_MID 1
#define RRIP_MRU 0

// LRU parameters
struct BlockState {
    uint8_t rrip;     // For SRRIP/BIP
    uint8_t lru;      // For LRU
};

struct SetState {
    std::vector<BlockState> blocks;
    // Phase detection
    uint32_t recent_hits;
    uint32_t recent_misses;
    uint8_t mode; // 0:SRRIP, 1:LRU, 2:BIP
};

std::vector<SetState> sets(LLC_SETS);

// --- Helper: Find LRU victim ---
uint32_t FindLRUVictim(SetState &ss) {
    uint8_t max_lru = 0;
    uint32_t victim = 0;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (ss.blocks[w].lru >= max_lru) {
            max_lru = ss.blocks[w].lru;
            victim = w;
        }
    }
    return victim;
}

// --- Helper: Find RRIP victim ---
uint32_t FindRRIPVictim(SetState &ss) {
    // Prefer RRIP==RRIP_MAX
    for (uint32_t loop = 0; loop < 2; ++loop) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ss.blocks[w].rrip == RRIP_MAX)
                return w;
        }
        // If none found, increment RRIP counters
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (ss.blocks[w].rrip < RRIP_MAX)
                ss.blocks[w].rrip++;
    }
    // Fallback
    return 0;
}

// --- Helper: Find BIP victim (same as RRIP) ---
uint32_t FindBIPVictim(SetState &ss) {
    return FindRRIPVictim(ss);
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].rrip = RRIP_MAX;
            sets[s].blocks[w].lru = w;
        }
        sets[s].recent_hits = 0;
        sets[s].recent_misses = 0;
        sets[s].mode = 0; // Start in SRRIP mode
    }
}

// --- Find victim in the set ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState &ss = sets[set];
    if (ss.mode == 1) // LRU phase
        return FindLRUVictim(ss);
    else if (ss.mode == 2) // BIP phase
        return FindBIPVictim(ss);
    else // SRRIP phase
        return FindRRIPVictim(ss);
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
    SetState &ss = sets[set];
    // --- Phase detection ---
    if (hit)
        ss.recent_hits++;
    else
        ss.recent_misses++;

    // Every 64 accesses, check phase
    if ((ss.recent_hits + ss.recent_misses) >= 64) {
        // If hit rate > 70%, switch to LRU (temporal locality)
        if (ss.recent_hits > 45)
            ss.mode = 1;
        // If miss rate > 80%, switch to BIP (streaming/pointer-chase)
        else if (ss.recent_misses > 51)
            ss.mode = 2;
        // Otherwise, use SRRIP (mixed/regular)
        else
            ss.mode = 0;
        ss.recent_hits = 0;
        ss.recent_misses = 0;
    }

    // --- Update block states ---
    if (ss.mode == 1) { // LRU
        // Promote to MRU on hit
        if (hit) {
            uint8_t old_lru = ss.blocks[way].lru;
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (ss.blocks[w].lru < old_lru)
                    ss.blocks[w].lru++;
            ss.blocks[way].lru = 0;
        } else {
            // Insert as MRU
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                ss.blocks[w].lru++;
            ss.blocks[way].lru = 0;
        }
        // RRIP not used
    }
    else if (ss.mode == 2) { // BIP
        // On miss, insert with RRIP_MAX (low priority) 95% of time, RRIP_MRU 5% of time
        static uint32_t bip_counter = 0;
        if (!hit) {
            bip_counter++;
            if (bip_counter % 20 == 0)
                ss.blocks[way].rrip = RRIP_MRU; // Occasionally insert as MRU
            else
                ss.blocks[way].rrip = RRIP_MAX;
        } else {
            ss.blocks[way].rrip = RRIP_MRU; // Promote to MRU on hit
        }
        // LRU not used
    }
    else { // SRRIP
        if (hit)
            ss.blocks[way].rrip = RRIP_MRU; // Promote to MRU
        else
            ss.blocks[way].rrip = RRIP_MID; // Insert with mid priority
        // LRU not used
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    // Print mode distribution for first 4 sets
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " mode: ";
        if (sets[s].mode == 0) std::cout << "SRRIP";
        else if (sets[s].mode == 1) std::cout << "LRU";
        else std::cout << "BIP";
        std::cout << "\n";
    }
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    // No-op
}