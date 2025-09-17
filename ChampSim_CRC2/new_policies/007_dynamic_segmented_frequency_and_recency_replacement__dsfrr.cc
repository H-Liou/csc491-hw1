#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DSFRR parameters
#define PROTECTED_WAYS 6 // Number of ways in protected segment per set
#define PROBATIONARY_WAYS (LLC_WAYS - PROTECTED_WAYS)
#define FREQ_BITS 2      // 2-bit frequency counter per block
#define FREQ_PROMOTE 2   // Promotion threshold
#define FREQ_MAX ((1 << FREQ_BITS) - 1)

struct BlockMeta {
    bool valid;
    uint8_t freq;   // Frequency counter
    uint8_t lru;    // LRU position within segment
    uint64_t tag;   // Block tag for matching
};

struct SetMeta {
    BlockMeta protected_blocks[PROTECTED_WAYS];
    BlockMeta probationary_blocks[PROBATIONARY_WAYS];
};

std::vector<SetMeta> sets;

// Helper: find block in segment by tag, return index or -1
int find_block(BlockMeta* blocks, int num_ways, uint64_t tag) {
    for (int i = 0; i < num_ways; ++i)
        if (blocks[i].valid && blocks[i].tag == tag)
            return i;
    return -1;
}

// Helper: update LRU in segment (move block to MRU)
void update_lru(BlockMeta* blocks, int num_ways, int hit_idx) {
    uint8_t old_lru = blocks[hit_idx].lru;
    blocks[hit_idx].lru = 0;
    for (int i = 0; i < num_ways; ++i) {
        if (i == hit_idx) continue;
        if (blocks[i].valid && blocks[i].lru < old_lru)
            blocks[i].lru++;
    }
}

// Initialize replacement state
void InitReplacementState() {
    sets.clear();
    sets.resize(LLC_SETS);
    for (auto& set : sets) {
        for (int i = 0; i < PROTECTED_WAYS; ++i) {
            set.protected_blocks[i].valid = false;
            set.protected_blocks[i].freq = 0;
            set.protected_blocks[i].lru = i;
            set.protected_blocks[i].tag = 0;
        }
        for (int i = 0; i < PROBATIONARY_WAYS; ++i) {
            set.probationary_blocks[i].valid = false;
            set.probationary_blocks[i].freq = 0;
            set.probationary_blocks[i].lru = i;
            set.probationary_blocks[i].tag = 0;
        }
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

    // Prefer to evict from probationary segment first
    for (int i = 0; i < PROBATIONARY_WAYS; ++i) {
        if (!meta.probationary_blocks[i].valid)
            return PROTECTED_WAYS + i; // way index in LLC
    }
    // Find LRU in probationary
    int lru_idx = 0;
    uint8_t max_lru = 0;
    for (int i = 0; i < PROBATIONARY_WAYS; ++i) {
        if (meta.probationary_blocks[i].lru >= max_lru) {
            max_lru = meta.probationary_blocks[i].lru;
            lru_idx = i;
        }
    }
    return PROTECTED_WAYS + lru_idx;

    // If all probationary blocks are valid and protected, evict LRU from protected
    // (unlikely, but fallback)
    int lru_p_idx = 0;
    max_lru = 0;
    for (int i = 0; i < PROTECTED_WAYS; ++i) {
        if (meta.protected_blocks[i].lru >= max_lru) {
            max_lru = meta.protected_blocks[i].lru;
            lru_p_idx = i;
        }
    }
    return lru_p_idx;
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
    uint64_t tag = (paddr >> 6); // Assume 64B lines

    // Determine which segment and index
    if (way < PROTECTED_WAYS) {
        // Protected segment
        int idx = way;
        if (hit) {
            if (meta.protected_blocks[idx].freq < FREQ_MAX)
                meta.protected_blocks[idx].freq++;
            update_lru(meta.protected_blocks, PROTECTED_WAYS, idx);
        } else {
            // On miss, do nothing (block will be replaced if chosen as victim)
        }
    } else {
        // Probationary segment
        int idx = way - PROTECTED_WAYS;
        if (hit) {
            if (meta.probationary_blocks[idx].freq < FREQ_MAX)
                meta.probationary_blocks[idx].freq++;
            update_lru(meta.probationary_blocks, PROBATIONARY_WAYS, idx);

            // If frequency exceeds threshold, promote to protected
            if (meta.probationary_blocks[idx].freq >= FREQ_PROMOTE) {
                // Find LRU in protected to evict
                int lru_p_idx = 0;
                uint8_t max_lru = 0;
                for (int i = 0; i < PROTECTED_WAYS; ++i) {
                    if (meta.protected_blocks[i].lru >= max_lru) {
                        max_lru = meta.protected_blocks[i].lru;
                        lru_p_idx = i;
                    }
                }
                // Evict protected block
                meta.protected_blocks[lru_p_idx] = meta.probationary_blocks[idx];
                meta.protected_blocks[lru_p_idx].lru = 0;
                // Invalidate probationary block
                meta.probationary_blocks[idx].valid = false;
                meta.probationary_blocks[idx].freq = 0;
                meta.probationary_blocks[idx].lru = PROBATIONARY_WAYS - 1;
                meta.probationary_blocks[idx].tag = 0;
                // Update LRU in protected
                for (int i = 0; i < PROTECTED_WAYS; ++i) {
                    if (i != lru_p_idx && meta.protected_blocks[i].valid)
                        meta.protected_blocks[i].lru++;
                }
            }
        } else {
            // On miss, insert new block into probationary (replace LRU)
            int victim_idx = idx;
            meta.probationary_blocks[victim_idx].valid = true;
            meta.probationary_blocks[victim_idx].freq = 1;
            meta.probationary_blocks[victim_idx].lru = 0;
            meta.probationary_blocks[victim_idx].tag = tag;
            // Update LRU in probationary
            for (int i = 0; i < PROBATIONARY_WAYS; ++i) {
                if (i != victim_idx && meta.probationary_blocks[i].valid)
                    meta.probationary_blocks[i].lru++;
            }
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Optional: print protected/probationary occupancy
    uint64_t total_protected = 0, total_probationary = 0;
    for (const auto& set : sets) {
        for (int i = 0; i < PROTECTED_WAYS; ++i)
            if (set.protected_blocks[i].valid) total_protected++;
        for (int i = 0; i < PROBATIONARY_WAYS; ++i)
            if (set.probationary_blocks[i].valid) total_probationary++;
    }
    std::cout << "Protected blocks: " << total_protected << " Probationary blocks: " << total_probationary << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}