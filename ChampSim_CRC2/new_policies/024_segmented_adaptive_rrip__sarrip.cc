#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_PROTECTED_INSERT 0   // Insert protected with RRIP=0
#define RRIP_PROBATIONARY_INSERT RRIP_MAX // Insert probationary with RRIP=3

// Segmentation constants
#define PROTECTED_WAYS 4 // 1/4 of the set is protected
#define PROBATIONARY_WAYS (LLC_WAYS - PROTECTED_WAYS)

struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
    uint8_t protected_block; // 1 if in protected segment, 0 if probationary
};

struct SetState {
    std::vector<BlockMeta> meta;
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0, 0});
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
    SetState& s = sets[set];

    // Prefer invalid in probationary segment
    for (uint32_t way = PROTECTED_WAYS; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }
    // If no invalid, evict RRIP_MAX in probationary segment
    for (uint32_t round = 0; round < 2; round++) {
        for (uint32_t way = PROTECTED_WAYS; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip == RRIP_MAX)
                return way;
        }
        // Aging: increment RRIP in probationary segment
        for (uint32_t way = PROTECTED_WAYS; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip < RRIP_MAX)
                s.meta[way].rrip++;
        }
    }
    // If probationary full, evict RRIP_MAX in protected segment
    for (uint32_t round = 0; round < 2; round++) {
        for (uint32_t way = 0; way < PROTECTED_WAYS; way++) {
            if (s.meta[way].rrip == RRIP_MAX)
                return way;
        }
        // Aging: increment RRIP in protected segment
        for (uint32_t way = 0; way < PROTECTED_WAYS; way++) {
            if (s.meta[way].rrip < RRIP_MAX)
                s.meta[way].rrip++;
        }
    }
    // Fallback: evict LRU in probationary segment
    uint32_t victim = PROTECTED_WAYS;
    uint8_t max_rrip = 0;
    for (uint32_t way = PROTECTED_WAYS; way < LLC_WAYS; way++) {
        if (s.meta[way].rrip >= max_rrip) {
            max_rrip = s.meta[way].rrip;
            victim = way;
        }
    }
    return victim;
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
    SetState& s = sets[set];
    uint64_t tag = paddr >> 6;

    if (hit) {
        // On hit: promote to protected segment if not already
        if (!s.meta[way].protected_block) {
            // Find LRU protected block to demote
            uint32_t demote_way = 0;
            uint8_t max_rrip = 0;
            for (uint32_t w = 0; w < PROTECTED_WAYS; w++) {
                if (s.meta[w].rrip >= max_rrip) {
                    max_rrip = s.meta[w].rrip;
                    demote_way = w;
                }
            }
            // Swap metadata: demote protected, promote probationary
            std::swap(s.meta[way], s.meta[demote_way]);
            s.meta[demote_way].protected_block = 0;
            s.meta[way].protected_block = 1;
            s.meta[way].rrip = RRIP_PROTECTED_INSERT;
            s.meta[way].valid = 1;
            s.meta[way].tag = tag;
        } else {
            // Already protected: reset RRIP
            s.meta[way].rrip = RRIP_PROTECTED_INSERT;
        }
    } else {
        // On miss/insertion: insert into probationary segment
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].protected_block = 0;
        s.meta[way].rrip = RRIP_PROBATIONARY_INSERT;
    }
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "SARRIP: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}