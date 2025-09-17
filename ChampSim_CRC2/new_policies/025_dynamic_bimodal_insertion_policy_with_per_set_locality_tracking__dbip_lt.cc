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
#define RRIP_LONG 0     // Low RRIP: keep long
#define RRIP_SHORT RRIP_MAX // High RRIP: evict soon

// BIP constants
#define BIP_PROB 32     // 1 out of 32 insertions use RRIP_LONG

// Per-set locality tracking
#define LOCALITY_MAX 7
#define LOCALITY_MIN 0
#define LOCALITY_THRESHOLD 3

struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
};

struct SetState {
    std::vector<BlockMeta> meta;
    uint8_t locality_counter; // tracks recent reuse (0-7)
    uint32_t bip_ptr;         // For BIP probabilistic insertion
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0});
        set.locality_counter = 0;
        set.bip_ptr = 0;
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

    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }
    // Evict RRIP_MAX block
    for (uint32_t round = 0; round < 2; round++) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip == RRIP_MAX)
                return way;
        }
        // Aging: increment RRIP of all blocks
        // More aggressive if locality is low
        uint8_t aging = (s.locality_counter <= LOCALITY_THRESHOLD) ? 2 : 1;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            s.meta[way].rrip = std::min<uint8_t>(RRIP_MAX, s.meta[way].rrip + aging);
        }
    }
    // Fallback: evict block with maximal RRIP value
    uint32_t victim = 0;
    uint8_t max_rrip = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
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
        // On hit: reset RRIP, increment locality counter
        s.meta[way].rrip = RRIP_LONG;
        if (s.locality_counter < LOCALITY_MAX)
            s.locality_counter++;
    } else {
        // On miss/insertion: use BIP+locality
        bool bip_insert = (s.bip_ptr == 0);
        s.bip_ptr = (s.bip_ptr + 1) % BIP_PROB;

        uint8_t insert_rrip;
        if (bip_insert) {
            insert_rrip = RRIP_LONG; // Give a chance for new blocks
        } else {
            // If set shows locality, retain; else, evict soon
            insert_rrip = (s.locality_counter > LOCALITY_THRESHOLD) ? RRIP_LONG : RRIP_SHORT;
        }
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].rrip = insert_rrip;

        // Decay locality counter if miss (streaming/irregular)
        if (s.locality_counter > LOCALITY_MIN)
            s.locality_counter--;
    }
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "DBIP-LT: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}