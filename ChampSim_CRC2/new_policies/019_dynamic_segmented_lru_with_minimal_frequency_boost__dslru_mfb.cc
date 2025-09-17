#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Segmentation parameters
#define HOT_WAYS 6        // Number of ways reserved for "hot" segment
#define COLD_WAYS (LLC_WAYS - HOT_WAYS)
#define FREQ_BITS 2       // 2-bit frequency counter for cold blocks
#define PROMOTE_THRESHOLD 2 // Promote to hot if reused twice in cold

struct BlockMeta {
    uint8_t valid;
    uint64_t tag;
    uint8_t lru;      // Position in LRU stack within segment
    uint8_t freq;     // Frequency counter (cold segment only)
    bool is_hot;      // Segment flag
};

struct SetState {
    std::vector<BlockMeta> meta;
    // LRU stacks for hot and cold segments
    std::vector<uint8_t> hot_lru_stack;  // indices of hot blocks, MRU at front
    std::vector<uint8_t> cold_lru_stack; // indices of cold blocks, MRU at front
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, 0, 0, false});
        set.hot_lru_stack.clear();
        set.cold_lru_stack.clear();
        // Initially, all blocks are cold and invalid
        for (uint8_t i = 0; i < LLC_WAYS; i++)
            set.cold_lru_stack.push_back(i);
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

    // Prefer invalid block in cold segment
    for (uint8_t idx : s.cold_lru_stack) {
        if (!s.meta[idx].valid)
            return idx;
    }
    // Prefer invalid block in hot segment
    for (uint8_t idx : s.hot_lru_stack) {
        if (!s.meta[idx].valid)
            return idx;
    }

    // If cold segment has any blocks, evict LRU cold block
    if (!s.cold_lru_stack.empty())
        return s.cold_lru_stack.back();

    // Else, evict LRU hot block (only if all blocks are hot)
    return s.hot_lru_stack.back();
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

    BlockMeta& block = s.meta[way];

    // On hit
    if (hit) {
        if (block.is_hot) {
            // Move to MRU in hot segment
            auto it = std::find(s.hot_lru_stack.begin(), s.hot_lru_stack.end(), way);
            if (it != s.hot_lru_stack.end()) {
                s.hot_lru_stack.erase(it);
                s.hot_lru_stack.insert(s.hot_lru_stack.begin(), way);
            }
        } else {
            // Increment frequency in cold segment
            if (block.freq < ((1 << FREQ_BITS) - 1))
                block.freq++;
            // Promote to hot if frequency threshold met
            if (block.freq >= PROMOTE_THRESHOLD) {
                block.is_hot = true;
                // Remove from cold LRU stack
                auto it = std::find(s.cold_lru_stack.begin(), s.cold_lru_stack.end(), way);
                if (it != s.cold_lru_stack.end())
                    s.cold_lru_stack.erase(it);
                // Add to hot LRU stack MRU
                s.hot_lru_stack.insert(s.hot_lru_stack.begin(), way);
                block.lru = 0;
            } else {
                // Move to MRU in cold segment
                auto it = std::find(s.cold_lru_stack.begin(), s.cold_lru_stack.end(), way);
                if (it != s.cold_lru_stack.end()) {
                    s.cold_lru_stack.erase(it);
                    s.cold_lru_stack.insert(s.cold_lru_stack.begin(), way);
                }
            }
        }
    } else { // On miss/insertion
        // Insert as cold block
        block.valid = 1;
        block.tag = tag;
        block.freq = 1;
        block.is_hot = false;
        block.lru = 0;

        // Remove from hot stack if present
        auto it_hot = std::find(s.hot_lru_stack.begin(), s.hot_lru_stack.end(), way);
        if (it_hot != s.hot_lru_stack.end())
            s.hot_lru_stack.erase(it_hot);

        // Remove from cold stack if present
        auto it_cold = std::find(s.cold_lru_stack.begin(), s.cold_lru_stack.end(), way);
        if (it_cold != s.cold_lru_stack.end())
            s.cold_lru_stack.erase(it_cold);

        // Insert at MRU of cold segment
        s.cold_lru_stack.insert(s.cold_lru_stack.begin(), way);

        // If cold segment exceeds limit, demote LRU cold block
        while (s.cold_lru_stack.size() > COLD_WAYS) {
            uint8_t lru_idx = s.cold_lru_stack.back();
            s.cold_lru_stack.pop_back();
            // If block is valid, evict it
            if (s.meta[lru_idx].valid) {
                s.meta[lru_idx].valid = 0;
                // stats
                total_evictions++;
            }
        }
        // If hot segment exceeds limit, demote LRU hot block to cold
        while (s.hot_lru_stack.size() > HOT_WAYS) {
            uint8_t lru_idx = s.hot_lru_stack.back();
            s.hot_lru_stack.pop_back();
            s.meta[lru_idx].is_hot = false;
            s.meta[lru_idx].freq = 1;
            // Move to MRU of cold segment
            auto it_cold2 = std::find(s.cold_lru_stack.begin(), s.cold_lru_stack.end(), lru_idx);
            if (it_cold2 != s.cold_lru_stack.end())
                s.cold_lru_stack.erase(it_cold2);
            s.cold_lru_stack.insert(s.cold_lru_stack.begin(), lru_idx);
        }
    }
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "DSLRU-MFB: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}