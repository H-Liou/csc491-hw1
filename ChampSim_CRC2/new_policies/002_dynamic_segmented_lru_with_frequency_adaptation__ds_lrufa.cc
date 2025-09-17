#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Segment boundaries
#define MIN_LRU_WAYS 4
#define MAX_LRU_WAYS 14
#define INIT_LRU_WAYS 8
#define SEGMENT_ADAPT_INTERVAL 128 // accesses per set before adaptation

// Frequency counter
#define FREQ_BITS 2
#define MAX_FREQ ((1 << FREQ_BITS) - 1)
#define FREQ_PROMOTE_THRESHOLD 2

struct BlockMeta {
    uint8_t freq;
    bool in_lru;
};

struct SetMeta {
    uint8_t lru_ways; // number of ways in LRU segment
    uint32_t access_count;
    uint32_t hit_count;
    std::vector<uint32_t> lru_list; // indices in LRU segment, MRU at front
    std::vector<uint32_t> fifo_list; // indices in FIFO segment, oldest at front
    BlockMeta blocks[LLC_WAYS];
    SetMeta() : lru_ways(INIT_LRU_WAYS), access_count(0), hit_count(0) {
        lru_list.reserve(MAX_LRU_WAYS);
        fifo_list.reserve(LLC_WAYS - MIN_LRU_WAYS);
        for (int i = 0; i < LLC_WAYS; ++i) {
            blocks[i].freq = 0;
            blocks[i].in_lru = (i < INIT_LRU_WAYS);
            if (i < INIT_LRU_WAYS) lru_list.push_back(i);
            else fifo_list.push_back(i);
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

    // Prefer FIFO segment blocks with freq==0 for eviction
    for (uint32_t idx : meta.fifo_list) {
        if (meta.blocks[idx].freq == 0)
            return idx;
    }
    // Otherwise, evict oldest in FIFO segment
    if (!meta.fifo_list.empty())
        return meta.fifo_list.front();

    // If FIFO segment empty (rare), evict LRU in LRU segment
    if (!meta.lru_list.empty())
        return meta.lru_list.back();

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

    if (hit) meta.hit_count++;

    // Find segment membership
    bool was_in_lru = meta.blocks[way].in_lru;

    // On hit: promote in LRU, or migrate from FIFO to LRU
    if (hit) {
        meta.blocks[way].freq = std::min<uint8_t>(meta.blocks[way].freq + 1, MAX_FREQ);

        if (was_in_lru) {
            // Move to MRU in LRU segment
            auto it = std::find(meta.lru_list.begin(), meta.lru_list.end(), way);
            if (it != meta.lru_list.end()) {
                meta.lru_list.erase(it);
                meta.lru_list.insert(meta.lru_list.begin(), way);
            }
        } else {
            // If freq above threshold, migrate to LRU segment
            if (meta.blocks[way].freq >= FREQ_PROMOTE_THRESHOLD) {
                // Remove from FIFO
                auto it = std::find(meta.fifo_list.begin(), meta.fifo_list.end(), way);
                if (it != meta.fifo_list.end()) meta.fifo_list.erase(it);
                // Add to MRU of LRU
                meta.lru_list.insert(meta.lru_list.begin(), way);
                meta.blocks[way].in_lru = true;
                // If LRU segment exceeds size, demote LRU to FIFO
                if (meta.lru_list.size() > meta.lru_ways) {
                    uint32_t demote = meta.lru_list.back();
                    meta.lru_list.pop_back();
                    meta.fifo_list.push_back(demote);
                    meta.blocks[demote].in_lru = false;
                }
            }
        }
    } else {
        // On miss: reset freq, insert into FIFO segment
        meta.blocks[way].freq = 0;
        if (was_in_lru) {
            // Remove from LRU
            auto it = std::find(meta.lru_list.begin(), meta.lru_list.end(), way);
            if (it != meta.lru_list.end()) meta.lru_list.erase(it);
            // Add to FIFO
            meta.fifo_list.push_back(way);
            meta.blocks[way].in_lru = false;
        } else {
            // Move to back of FIFO (oldest)
            auto it = std::find(meta.fifo_list.begin(), meta.fifo_list.end(), way);
            if (it != meta.fifo_list.end()) {
                meta.fifo_list.erase(it);
                meta.fifo_list.push_back(way);
            }
        }
    }

    // Adapt segment boundary every SEGMENT_ADAPT_INTERVAL accesses
    if (meta.access_count % SEGMENT_ADAPT_INTERVAL == 0) {
        float hit_rate = float(meta.hit_count) / float(SEGMENT_ADAPT_INTERVAL);
        // If hit rate high, expand LRU segment
        if (hit_rate > 0.5 && meta.lru_ways < MAX_LRU_WAYS) meta.lru_ways++;
        // If hit rate low, shrink LRU segment
        if (hit_rate < 0.2 && meta.lru_ways > MIN_LRU_WAYS) meta.lru_ways--;
        meta.hit_count = 0;
        // Rebalance segments if needed
        while (meta.lru_list.size() > meta.lru_ways) {
            uint32_t demote = meta.lru_list.back();
            meta.lru_list.pop_back();
            meta.fifo_list.push_back(demote);
            meta.blocks[demote].in_lru = false;
        }
        while (meta.lru_list.size() < meta.lru_ways && !meta.fifo_list.empty()) {
            uint32_t promote = meta.fifo_list.front();
            meta.fifo_list.erase(meta.fifo_list.begin());
            meta.lru_list.push_back(promote);
            meta.blocks[promote].in_lru = true;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Optionally print segment sizes and hit rates
    uint64_t total_lru = 0;
    for (const auto& meta : sets)
        total_lru += meta.lru_ways;
    std::cout << "Average LRU segment size: " << double(total_lru) / LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print stats
}