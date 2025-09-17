#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP constants ---
#define RRIP_MAX 3 // 2-bit RRIP
#define RRIP_INIT_LONG 2 // Insert as "long re-reference" by default

// --- Bloom filter constants ---
#define BLOOM_BITS 64
#define BLOOM_HASHES 2

// --- Block replacement state ---
struct BlockState {
    uint8_t rrip;          // RRIP value (0=MRU, 3=LRU)
    uint32_t spatial_tag;  // Page-based tag (for Bloom filter)
    uint64_t last_access;  // For stats/tiebreak
};

std::vector<std::vector<BlockState>> block_state(LLC_SETS, std::vector<BlockState>(LLC_WAYS));

// --- Per-set Bloom filter for locality protection ---
struct BloomFilter {
    uint64_t bits;
    // Simple hash functions for spatial tags
    inline void insert(uint32_t tag) {
        bits |= (1ULL << (tag % BLOOM_BITS));
        bits |= (1ULL << ((tag / 17) % BLOOM_BITS));
    }
    inline bool query(uint32_t tag) const {
        return ((bits & (1ULL << (tag % BLOOM_BITS))) &&
                (bits & (1ULL << ((tag / 17) % BLOOM_BITS))));
    }
    inline void clear() {
        bits = 0;
    }
};

std::vector<BloomFilter> set_bloom(LLC_SETS);

// --- Global stats ---
uint64_t global_access_counter = 0;
uint64_t total_evictions = 0;

// --- Utility: spatial group hash ---
inline uint32_t spatial_hash(uint64_t addr) {
    // Page-based grouping (e.g., 4KB)
    return (uint32_t)((addr >> 12) & 0xFFFF);
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_state[set][way] = {RRIP_MAX, 0, 0};
        }
        set_bloom[set].clear();
    }
    global_access_counter = 0;
    total_evictions = 0;
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
    global_access_counter++;

    // First, try to find block with RRIP==RRIP_MAX and NOT protected by Bloom
    int victim = -1;
    uint32_t curr_tag = spatial_hash(paddr);
    BloomFilter& bloom = set_bloom[set];

    for (int way = 0; way < LLC_WAYS; ++way) {
        BlockState& bs = block_state[set][way];
        // If RRIP max and not protected
        if (bs.rrip == RRIP_MAX && !bloom.query(bs.spatial_tag)) {
            victim = way;
            break;
        }
    }
    // If not found, try RRIP==RRIP_MAX (even if protected)
    if (victim == -1) {
        for (int way = 0; way < LLC_WAYS; ++way) {
            BlockState& bs = block_state[set][way];
            if (bs.rrip == RRIP_MAX) {
                victim = way;
                break;
            }
        }
    }
    // If still not found, increment RRIP of all blocks and retry
    if (victim == -1) {
        for (int way = 0; way < LLC_WAYS; ++way) {
            BlockState& bs = block_state[set][way];
            if (bs.rrip < RRIP_MAX)
                bs.rrip++;
        }
        // Now pick RRIP==RRIP_MAX (ignore Bloom)
        for (int way = 0; way < LLC_WAYS; ++way) {
            BlockState& bs = block_state[set][way];
            if (bs.rrip == RRIP_MAX) {
                victim = way;
                break;
            }
        }
    }
    // Defensive: fallback to LRU if all else fails
    if (victim == -1) {
        uint64_t oldest = block_state[set][0].last_access;
        victim = 0;
        for (int way = 1; way < LLC_WAYS; ++way) {
            if (block_state[set][way].last_access < oldest) {
                oldest = block_state[set][way].last_access;
                victim = way;
            }
        }
    }
    total_evictions++;
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
    global_access_counter++;
    BlockState& bs = block_state[set][way];
    BloomFilter& bloom = set_bloom[set];

    uint32_t curr_tag = spatial_hash(paddr);

    // On hit: promote block (set RRIP=0), update last access, insert tag to Bloom
    if (hit) {
        bs.rrip = 0;
        bs.last_access = global_access_counter;
        bs.spatial_tag = curr_tag;
        bloom.insert(curr_tag);
    }
    // On miss: insert new block with RRIP_INIT_LONG, update spatial tag, insert tag to Bloom
    else {
        bs.rrip = RRIP_INIT_LONG;
        bs.last_access = global_access_counter;
        bs.spatial_tag = curr_tag;
        bloom.insert(curr_tag);
    }

    // Periodically clear Bloom to adapt to phase changes (every 8192 accesses per set)
    if ((global_access_counter & 0x1FFF) == 0) {
        bloom.clear();
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "HRBR: total_evictions=" << total_evictions << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    PrintStats();
}