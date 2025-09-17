#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP parameters
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_LONG RRIP_MAX      // Insert as "distant re-reference"
#define RRIP_SHORT 0            // Promote to "imminent re-reference"
#define RRIP_MEDIUM 1           // Insert as "medium re-reference"

// Frequency tracking parameters
#define FREQ_MAX 7              // 3-bit saturating counter
#define FREQ_DECAY_INTERVAL 256 // Decay frequency every N accesses

// Hit rate adaptation parameters
#define HITRATE_WINDOW 128
#define HITRATE_HIGH 0.40
#define HITRATE_LOW 0.18

struct BlockMeta {
    uint8_t rrip;      // RRIP value
    uint8_t freq;      // Frequency counter
    bool valid;
};

struct SetMeta {
    BlockMeta blocks[LLC_WAYS];
    uint32_t access_count;
    uint32_t hit_count;
    bool high_locality; // If true, insert with RRIP_MEDIUM, else RRIP_LONG
    SetMeta() : access_count(0), hit_count(0), high_locality(false) {
        for (int i = 0; i < LLC_WAYS; ++i) {
            blocks[i].rrip = RRIP_MAX;
            blocks[i].freq = 0;
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

    // Prefer invalid blocks first
    for (uint32_t i = 0; i < LLC_WAYS; ++i)
        if (!meta.blocks[i].valid)
            return i;

    // Find blocks with RRIP_MAX, among them pick one with lowest freq
    uint32_t victim = 0;
    uint8_t min_freq = FREQ_MAX + 1;
    bool found = false;
    for (uint32_t i = 0; i < LLC_WAYS; ++i) {
        if (meta.blocks[i].rrip == RRIP_MAX) {
            found = true;
            if (meta.blocks[i].freq < min_freq) {
                min_freq = meta.blocks[i].freq;
                victim = i;
            }
        }
    }
    if (found)
        return victim;

    // If none found, increment RRIP of all blocks and retry
    for (uint32_t i = 0; i < LLC_WAYS; ++i)
        if (meta.blocks[i].rrip < RRIP_MAX)
            meta.blocks[i].rrip++;

    // Retry: find RRIP_MAX with lowest freq
    min_freq = FREQ_MAX + 1;
    found = false;
    for (uint32_t i = 0; i < LLC_WAYS; ++i) {
        if (meta.blocks[i].rrip == RRIP_MAX) {
            found = true;
            if (meta.blocks[i].freq < min_freq) {
                min_freq = meta.blocks[i].freq;
                victim = i;
            }
        }
    }
    if (found)
        return victim;

    // Fallback: evict way with lowest freq
    min_freq = FREQ_MAX + 1;
    for (uint32_t i = 0; i < LLC_WAYS; ++i) {
        if (meta.blocks[i].freq < min_freq) {
            min_freq = meta.blocks[i].freq;
            victim = i;
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
    SetMeta &meta = sets[set];
    meta.access_count++;

    if (hit) {
        meta.hit_count++;
        meta.blocks[way].rrip = RRIP_SHORT;
        // Saturate frequency counter
        if (meta.blocks[way].freq < FREQ_MAX)
            meta.blocks[way].freq++;
        meta.blocks[way].valid = true;
    } else {
        // On miss, insert block with RRIP_MEDIUM if high locality, else RRIP_LONG
        uint8_t insert_rrip = meta.high_locality ? RRIP_MEDIUM : RRIP_LONG;
        meta.blocks[way].rrip = insert_rrip;
        meta.blocks[way].freq = 0;
        meta.blocks[way].valid = true;
    }

    // Every HITRATE_WINDOW accesses, adapt insertion RRIP based on hit rate
    if (meta.access_count % HITRATE_WINDOW == 0) {
        float hit_rate = float(meta.hit_count) / float(HITRATE_WINDOW);
        if (hit_rate > HITRATE_HIGH)
            meta.high_locality = true;
        else if (hit_rate < HITRATE_LOW)
            meta.high_locality = false;
        // Reset counters
        meta.hit_count = 0;
    }

    // Decay frequency counters every FREQ_DECAY_INTERVAL accesses
    if (meta.access_count % FREQ_DECAY_INTERVAL == 0) {
        for (uint32_t i = 0; i < LLC_WAYS; ++i) {
            if (meta.blocks[i].freq > 0)
                meta.blocks[i].freq--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint64_t high_locality_sets = 0;
    for (const auto& meta : sets)
        if (meta.high_locality) high_locality_sets++;
    std::cout << "Fraction of sets in high locality mode: " << double(high_locality_sets) / LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}