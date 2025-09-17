#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define RRPV_LONG RRPV_MAX
#define RRPV_SHORT (RRPV_MAX - 1)
#define RRPV_PROMOTE 0

// Dynamic insertion threshold
#define ADAPT_WINDOW 32
#define ADAPT_MAX 15
#define ADAPT_MIN 1

struct BlockMeta {
    bool valid;
    uint64_t tag;
    uint8_t rrpv;
    uint64_t last_addr; // For segment-aware spatial locality
};

struct SetMeta {
    BlockMeta blocks[LLC_WAYS];
    // Adaptive insertion: track recent hits/misses
    int insert_policy; // 0: mostly long, 1: mostly short
    int hit_count;
    int miss_count;
    uint64_t last_insert_addr;
};

std::vector<SetMeta> sets;

// Initialize replacement state
void InitReplacementState() {
    sets.clear();
    sets.resize(LLC_SETS);
    for (auto& set : sets) {
        for (int i = 0; i < LLC_WAYS; ++i) {
            set.blocks[i].valid = false;
            set.blocks[i].tag = 0;
            set.blocks[i].rrpv = RRPV_LONG;
            set.blocks[i].last_addr = 0;
        }
        set.insert_policy = 0;
        set.hit_count = 0;
        set.miss_count = 0;
        set.last_insert_addr = 0;
    }
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
    // Try to find a block with RRPV_MAX
    for (int loop = 0; loop < 2; ++loop) {
        for (int i = 0; i < LLC_WAYS; ++i) {
            if (meta.blocks[i].valid && meta.blocks[i].rrpv == RRPV_MAX)
                return i;
            if (!meta.blocks[i].valid)
                return i; // Empty slot
        }
        // If none found, increment all RRPVs and repeat
        for (int i = 0; i < LLC_WAYS; ++i)
            if (meta.blocks[i].rrpv < RRPV_MAX)
                meta.blocks[i].rrpv++;
    }
    // Should not happen, but fallback to LRU
    uint32_t victim = 0;
    for (int i = 1; i < LLC_WAYS; ++i)
        if (meta.blocks[i].rrpv > meta.blocks[victim].rrpv)
            victim = i;
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
    uint64_t tag = (paddr >> 6); // 64B lines

    // Track adaptive insertion window
    if (hit)
        meta.hit_count++;
    else
        meta.miss_count++;

    // Every ADAPT_WINDOW accesses, adapt insertion policy
    if ((meta.hit_count + meta.miss_count) % ADAPT_WINDOW == 0) {
        if (meta.hit_count > meta.miss_count)
            meta.insert_policy = 1; // Favor short insertion (reuse likely)
        else
            meta.insert_policy = 0; // Favor long insertion (streaming)
        meta.hit_count = 0;
        meta.miss_count = 0;
    }

    BlockMeta &blk = meta.blocks[way];

    if (hit) {
        // On hit, promote block (lower RRPV)
        blk.rrpv = RRPV_PROMOTE;

        // Segment-aware: if access is spatially close to last insert, promote further
        if (std::abs((int64_t)paddr - (int64_t)blk.last_addr) < 512) // within 8 lines
            blk.rrpv = RRPV_PROMOTE;

        blk.last_addr = paddr;
    } else {
        // On miss, insert new block
        blk.valid = true;
        blk.tag = tag;
        blk.last_addr = paddr;

        // Segment-aware: If spatially close to previous insert, use short insertion
        if (std::abs((int64_t)paddr - (int64_t)meta.last_insert_addr) < 512)
            blk.rrpv = RRPV_SHORT;
        else
            blk.rrpv = (meta.insert_policy ? RRPV_SHORT : RRPV_LONG);

        meta.last_insert_addr = paddr;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print distribution of RRPVs
    uint64_t rrpv_hist[RRPV_MAX + 1] = {0};
    uint64_t valid_blocks = 0;
    for (const auto& set : sets) {
        for (int i = 0; i < LLC_WAYS; ++i) {
            if (set.blocks[i].valid) {
                rrpv_hist[set.blocks[i].rrpv]++;
                valid_blocks++;
            }
        }
    }
    std::cout << "RRPV distribution: ";
    for (int i = 0; i <= RRPV_MAX; ++i)
        std::cout << "[" << i << "]=" << rrpv_hist[i] << " ";
    std::cout << "Total valid blocks: " << valid_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}