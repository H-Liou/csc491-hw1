#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Segmented LRU parameters
#define PROTECTED_WAYS 6
#define PROBATION_WAYS (LLC_WAYS - PROTECTED_WAYS)

// Region counter parameters
#define REGION_BITS 14 // 16KB regions
#define REGION_TABLE_SIZE 4096
#define REGION_MAX 7
#define REGION_MIN 0
#define REGION_PROTECT_THRESHOLD 5
#define REGION_BYPASS_THRESHOLD 1

struct BlockMeta {
    bool valid;
    uint64_t tag;
    uint8_t lru; // 0 = MRU, higher = older
    bool protected_segment;
    uint16_t region_id;
};

struct SetMeta {
    BlockMeta blocks[LLC_WAYS];
};

std::vector<SetMeta> sets;

// Region table: tracks reuse for each region
struct RegionEntry {
    uint8_t reuse_counter;
};

std::vector<RegionEntry> region_table;

// Helper: get region id from address
inline uint16_t get_region_id(uint64_t paddr) {
    return (paddr >> REGION_BITS) % REGION_TABLE_SIZE;
}

// Initialize replacement state
void InitReplacementState() {
    sets.clear();
    sets.resize(LLC_SETS);
    for (auto& set : sets) {
        for (int i = 0; i < LLC_WAYS; ++i) {
            set.blocks[i].valid = false;
            set.blocks[i].tag = 0;
            set.blocks[i].lru = i; // initialize LRU order
            set.blocks[i].protected_segment = false;
            set.blocks[i].region_id = 0;
        }
    }
    region_table.clear();
    region_table.resize(REGION_TABLE_SIZE);
    for (auto& entry : region_table)
        entry.reuse_counter = 3; // neutral start
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

    // Check if region should be bypassed
    uint16_t region_id = get_region_id(paddr);
    uint8_t region_val = region_table[region_id].reuse_counter;
    if (region_val <= REGION_BYPASS_THRESHOLD) {
        // Indicate bypass by returning LLC_WAYS (invalid index)
        return LLC_WAYS;
    }

    // Prefer to evict from probation segment first
    int victim = -1;
    uint8_t oldest_lru = 0;
    for (int i = 0; i < LLC_WAYS; ++i) {
        if (!meta.blocks[i].valid) {
            return i; // empty slot
        }
        if (!meta.blocks[i].protected_segment) {
            if (victim == -1 || meta.blocks[i].lru > oldest_lru) {
                victim = i;
                oldest_lru = meta.blocks[i].lru;
            }
        }
    }
    if (victim != -1)
        return victim;

    // If all blocks are protected, evict oldest in protected segment
    victim = 0;
    oldest_lru = meta.blocks[0].lru;
    for (int i = 1; i < LLC_WAYS; ++i) {
        if (meta.blocks[i].lru > oldest_lru) {
            victim = i;
            oldest_lru = meta.blocks[i].lru;
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
    uint64_t tag = (paddr >> 6); // 64B lines
    uint16_t region_id = get_region_id(paddr);
    RegionEntry &region = region_table[region_id];

    // If bypassed, do nothing
    if (way == LLC_WAYS)
        return;

    BlockMeta &blk = meta.blocks[way];

    if (hit) {
        // Promote to MRU
        uint8_t old_lru = blk.lru;
        for (int i = 0; i < LLC_WAYS; ++i) {
            if (meta.blocks[i].lru < old_lru)
                meta.blocks[i].lru++;
        }
        blk.lru = 0;

        // If not protected and region is strong, promote to protected
        if (!blk.protected_segment && region.reuse_counter >= REGION_PROTECT_THRESHOLD) {
            // Find LRU in protected segment to demote
            int prot_lru = -1, prot_lru_val = -1;
            for (int i = 0; i < LLC_WAYS; ++i) {
                if (meta.blocks[i].protected_segment) {
                    if (meta.blocks[i].lru > prot_lru_val) {
                        prot_lru = i;
                        prot_lru_val = meta.blocks[i].lru;
                    }
                }
            }
            if (prot_lru != -1) {
                meta.blocks[prot_lru].protected_segment = false;
            }
            blk.protected_segment = true;
        }

        // Increment region reuse counter (up to max)
        if (region.reuse_counter < REGION_MAX)
            region.reuse_counter++;
    } else {
        // Insert new block
        blk.valid = true;
        blk.tag = tag;
        blk.region_id = region_id;

        // Assign segment based on region reuse
        if (region.reuse_counter >= REGION_PROTECT_THRESHOLD) {
            blk.protected_segment = true;
        } else {
            blk.protected_segment = false;
        }

        // Set LRU order: MRU
        uint8_t old_lru = blk.lru;
        for (int i = 0; i < LLC_WAYS; ++i) {
            if (meta.blocks[i].lru < old_lru)
                meta.blocks[i].lru++;
        }
        blk.lru = 0;

        // On insertion, decay region reuse counter (unless strong)
        if (region.reuse_counter > REGION_MIN)
            region.reuse_counter--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print region reuse counter histogram
    uint64_t hist[REGION_MAX+1] = {0};
    for (const auto& entry : region_table)
        hist[entry.reuse_counter]++;
    std::cout << "Region reuse counter histogram: ";
    for (int i = 0; i <= REGION_MAX; ++i)
        std::cout << "[" << i << "]=" << hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}