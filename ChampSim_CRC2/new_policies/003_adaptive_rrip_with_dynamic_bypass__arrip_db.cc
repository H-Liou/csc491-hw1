#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_LONG ((1 << RRIP_BITS) - 1)      // Insert as "distant re-reference"
#define RRIP_SHORT 0                          // Promote to "imminent re-reference"
#define RRIP_INSERT_PROB 0.2                  // Probability to insert when bypassing

// Bypass adaptation parameters
#define BYPASS_ADAPT_INTERVAL 128
#define BYPASS_HIT_LOW 0.15
#define BYPASS_HIT_HIGH 0.45

struct BlockMeta {
    uint8_t rrip; // RRIP value
    bool valid;
};

struct SetMeta {
    BlockMeta blocks[LLC_WAYS];
    uint32_t access_count;
    uint32_t hit_count;
    bool bypass_mode; // If true, bypass insertions
    SetMeta() : access_count(0), hit_count(0), bypass_mode(false) {
        for (int i = 0; i < LLC_WAYS; ++i) {
            blocks[i].rrip = RRIP_MAX;
            blocks[i].valid = false;
        }
    }
};

std::vector<SetMeta> sets;

// Initialize replacement state
void InitReplacementState() {
    sets.clear();
    sets.resize(LLC_SETS);
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
    SetMeta &meta = sets[set];

    // Find block with RRIP == RRIP_MAX (lowest re-reference probability)
    for (int round = 0; round < 2; ++round) {
        for (uint32_t i = 0; i < LLC_WAYS; ++i) {
            if (!meta.blocks[i].valid)
                return i; // Prefer invalid blocks for fill
            if (meta.blocks[i].rrip == RRIP_MAX)
                return i;
        }
        // If none found, increment RRIP of all blocks and retry
        for (uint32_t i = 0; i < LLC_WAYS; ++i)
            if (meta.blocks[i].rrip < RRIP_MAX)
                meta.blocks[i].rrip++;
    }
    // Fallback: evict way 0
    return 0;
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
    SetMeta &meta = sets[set];
    meta.access_count++;

    // On hit: promote block to RRIP_SHORT
    if (hit) {
        meta.hit_count++;
        meta.blocks[way].rrip = RRIP_SHORT;
        meta.blocks[way].valid = true;
    } else {
        // On miss: adaptive bypass logic
        bool insert = true;
        if (meta.bypass_mode) {
            // Bypass with high probability
            if ((rand() % 100) < (RRIP_INSERT_PROB * 100))
                insert = true;
            else
                insert = false;
        }
        if (insert) {
            // Insert block with RRIP_LONG (distant re-reference)
            meta.blocks[way].rrip = RRIP_LONG;
            meta.blocks[way].valid = true;
        } else {
            // Mark block as invalid (simulate bypass)
            meta.blocks[way].valid = false;
            meta.blocks[way].rrip = RRIP_MAX;
        }
    }

    // Every BYPASS_ADAPT_INTERVAL accesses, adapt bypass mode
    if (meta.access_count % BYPASS_ADAPT_INTERVAL == 0) {
        float hit_rate = float(meta.hit_count) / float(BYPASS_ADAPT_INTERVAL);
        // If hit rate is low, enable bypass mode
        if (hit_rate < BYPASS_HIT_LOW)
            meta.bypass_mode = true;
        // If hit rate is high, disable bypass mode
        else if (hit_rate > BYPASS_HIT_HIGH)
            meta.bypass_mode = false;
        // Reset counters
        meta.hit_count = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint64_t bypass_sets = 0;
    for (const auto& meta : sets)
        if (meta.bypass_mode) bypass_sets++;
    std::cout << "Fraction of sets in bypass mode: " << double(bypass_sets) / LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}