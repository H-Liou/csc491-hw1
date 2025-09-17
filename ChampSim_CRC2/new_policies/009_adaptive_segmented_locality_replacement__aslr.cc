#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Segmented set constants ---
#define LOC_SEG_WAYS 6   // Locality segment ways (dynamic boundary)
#define GEN_SEG_WAYS (LLC_WAYS - LOC_SEG_WAYS)
#define RRIP_MAX 3
#define RRIP_INIT_LONG 2

// --- Locality detection history ---
#define LOC_HISTORY_SIZE 8

struct BlockState {
    uint8_t rrip;
    uint32_t spatial_tag;    // Page-based tag
    uint64_t last_access;
    bool is_locality;        // Segment membership
};

std::vector<std::vector<BlockState>> block_state(LLC_SETS, std::vector<BlockState>(LLC_WAYS));

// Per-set recent page hash history for locality detection
struct LocalityHistory {
    uint32_t page_tags[LOC_HISTORY_SIZE];
    int ptr_tags[LOC_HISTORY_SIZE]; // For pointer-chasing detection (lower bits of address)
    int idx;
    LocalityHistory() : idx(0) {
        std::fill(page_tags, page_tags + LOC_HISTORY_SIZE, 0);
        std::fill(ptr_tags, ptr_tags + LOC_HISTORY_SIZE, -1);
    }
    void insert(uint32_t page, int ptr) {
        page_tags[idx % LOC_HISTORY_SIZE] = page;
        ptr_tags[idx % LOC_HISTORY_SIZE] = ptr;
        idx++;
    }
    bool page_recent(uint32_t page) const {
        for (int i = 0; i < LOC_HISTORY_SIZE; ++i)
            if (page_tags[i] == page) return true;
        return false;
    }
    bool ptr_recent(int ptr) const {
        for (int i = 0; i < LOC_HISTORY_SIZE; ++i)
            if (ptr_tags[i] == ptr) return true;
        return false;
    }
};

std::vector<LocalityHistory> set_history(LLC_SETS);

// Dynamic segment boundary (per set)
std::vector<int> loc_seg_ways(LLC_SETS, LOC_SEG_WAYS);

// --- Stats ---
uint64_t global_access_counter = 0;
uint64_t total_evictions = 0;
uint64_t locality_hits = 0;
uint64_t general_hits = 0;

// --- Utility: spatial group hash ---
inline uint32_t spatial_hash(uint64_t addr) {
    return (uint32_t)((addr >> 12) & 0xFFFF); // 4KB page
}
inline int pointer_tag(uint64_t addr) {
    return (int)((addr >> 3) & 0xFF); // lower bits for pointer-chasing
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_state[set][way] = {RRIP_MAX, 0, 0, false};
        }
        set_history[set] = LocalityHistory();
        loc_seg_ways[set] = LOC_SEG_WAYS;
    }
    global_access_counter = 0;
    total_evictions = 0;
    locality_hits = 0;
    general_hits = 0;
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
    int loc_ways = loc_seg_ways[set];
    int gen_ways = LLC_WAYS - loc_ways;

    // Prefer to evict from General segment unless Locality segment is full
    int victim = -1;

    // Check General segment for RRIP_MAX
    for (int way = loc_ways; way < LLC_WAYS; ++way) {
        BlockState& bs = block_state[set][way];
        if (bs.rrip == RRIP_MAX) {
            victim = way;
            break;
        }
    }
    // If not found, check Locality segment for RRIP_MAX
    if (victim == -1) {
        for (int way = 0; way < loc_ways; ++way) {
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
            if (block_state[set][way].rrip < RRIP_MAX)
                block_state[set][way].rrip++;
        }
        // Retry General segment
        for (int way = loc_ways; way < LLC_WAYS; ++way) {
            if (block_state[set][way].rrip == RRIP_MAX) {
                victim = way;
                break;
            }
        }
        // Retry Locality segment
        if (victim == -1) {
            for (int way = 0; way < loc_ways; ++way) {
                if (block_state[set][way].rrip == RRIP_MAX) {
                    victim = way;
                    break;
                }
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
    LocalityHistory& hist = set_history[set];
    int loc_ways = loc_seg_ways[set];

    uint32_t curr_page = spatial_hash(paddr);
    int curr_ptr = pointer_tag(paddr);

    // Locality detection: recent page or pointer tag
    bool is_locality = hist.page_recent(curr_page) || hist.ptr_recent(curr_ptr);

    // Insert into history
    hist.insert(curr_page, curr_ptr);

    // On hit: promote block, set RRIP=0, update segment
    if (hit) {
        bs.rrip = 0;
        bs.last_access = global_access_counter;
        bs.spatial_tag = curr_page;
        bs.is_locality = is_locality;
        if (is_locality) locality_hits++; else general_hits++;
    }
    // On miss: insert block, assign to segment
    else {
        bs.rrip = RRIP_INIT_LONG;
        bs.last_access = global_access_counter;
        bs.spatial_tag = curr_page;
        bs.is_locality = is_locality;
    }

    // If block is locality and not in Locality segment, swap in
    if (bs.is_locality && way >= loc_ways) {
        // Find LRU block in Locality segment to swap out
        int swap_out = 0;
        uint64_t oldest = block_state[set][0].last_access;
        for (int w = 1; w < loc_ways; ++w) {
            if (block_state[set][w].last_access < oldest) {
                oldest = block_state[set][w].last_access;
                swap_out = w;
            }
        }
        std::swap(block_state[set][way], block_state[set][swap_out]);
    }
    // If block is not locality and in Locality segment, swap out
    if (!bs.is_locality && way < loc_ways) {
        // Find LRU block in General segment to swap out
        int swap_out = loc_ways;
        uint64_t oldest = block_state[set][loc_ways].last_access;
        for (int w = loc_ways + 1; w < LLC_WAYS; ++w) {
            if (block_state[set][w].last_access < oldest) {
                oldest = block_state[set][w].last_access;
                swap_out = w;
            }
        }
        std::swap(block_state[set][way], block_state[set][swap_out]);
    }

    // Periodically adjust segment boundary based on hit stats (every 4096 accesses)
    if ((global_access_counter & 0xFFF) == 0) {
        int total_hits = locality_hits + general_hits;
        if (total_hits > 0) {
            double loc_ratio = (double)locality_hits / total_hits;
            if (loc_ratio > 0.7 && loc_seg_ways[set] < LLC_WAYS - 2)
                loc_seg_ways[set]++;
            else if (loc_ratio < 0.3 && loc_seg_ways[set] > 2)
                loc_seg_ways[set]--;
        }
        locality_hits = 0;
        general_hits = 0;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "ASLR: total_evictions=" << total_evictions << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    PrintStats();
}