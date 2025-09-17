#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Locality signals
#define REUSE_MAX 7
#define STREAM_STRIDE_WINDOW 8
#define STREAM_MATCH_THRESHOLD 6

struct BlockMeta {
    uint64_t tag;
    uint8_t lru;           // LRU stack position (0 = MRU)
    uint8_t reuse;         // Reuse counter
};

struct SetMeta {
    std::vector<BlockMeta> blocks;
    std::vector<int64_t> stride_hist;
    uint64_t last_addr;
};

std::vector<SetMeta> sets(LLC_SETS);

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].tag = 0;
            sets[s].blocks[w].lru = w;     // initialize LRU stack
            sets[s].blocks[w].reuse = 0;
        }
        sets[s].stride_hist.clear();
        sets[s].last_addr = 0;
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
    SetMeta &sm = sets[set];

    // --- Streaming detection ---
    int64_t stride = (sm.last_addr == 0) ? 0 : (int64_t)paddr - (int64_t)sm.last_addr;
    int stride_matches = 0;
    if (stride != 0 && sm.stride_hist.size() >= STREAM_MATCH_THRESHOLD) {
        stride_matches = std::count(sm.stride_hist.begin(), sm.stride_hist.end(), stride);
    }
    bool is_streaming = (stride_matches >= STREAM_MATCH_THRESHOLD);

    // --- Victim selection ---
    uint32_t victim = LLC_WAYS;
    uint8_t min_reuse = 255;
    uint8_t max_lru = 0;

    // Prefer blocks with low reuse, then LRU
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        uint8_t reuse = sm.blocks[w].reuse;
        uint8_t lru = sm.blocks[w].lru;

        // If streaming, prefer blocks with low reuse and high LRU (oldest)
        if (is_streaming) {
            if (reuse == 0 && lru >= max_lru) {
                victim = w;
                max_lru = lru;
            }
        } else {
            // Non-stream: prefer lowest reuse, break ties with LRU
            if (reuse < min_reuse || (reuse == min_reuse && lru > max_lru)) {
                victim = w;
                min_reuse = reuse;
                max_lru = lru;
            }
        }
    }
    // Fallback: LRU
    if (victim == LLC_WAYS) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (sm.blocks[w].lru == (LLC_WAYS - 1))
                return w;
        }
        return 0;
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
    SetMeta &sm = sets[set];

    // --- Update stride history ---
    int64_t stride = (sm.last_addr == 0) ? 0 : (int64_t)paddr - (int64_t)sm.last_addr;
    if (stride != 0) {
        sm.stride_hist.push_back(stride);
        if (sm.stride_hist.size() > STREAM_STRIDE_WINDOW)
            sm.stride_hist.erase(sm.stride_hist.begin());
    }
    sm.last_addr = paddr;

    // --- Streaming detection for insertion ---
    int stride_matches = 0;
    if (stride != 0 && sm.stride_hist.size() >= STREAM_MATCH_THRESHOLD) {
        stride_matches = std::count(sm.stride_hist.begin(), sm.stride_hist.end(), stride);
    }
    bool is_streaming = (stride_matches >= STREAM_MATCH_THRESHOLD);

    // --- Update LRU stack ---
    uint8_t old_lru = sm.blocks[way].lru;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (sm.blocks[w].lru < old_lru)
            sm.blocks[w].lru++;
    }
    sm.blocks[way].lru = 0;

    // --- Update reuse counter ---
    if (hit) {
        sm.blocks[way].reuse = std::min<uint8_t>(sm.blocks[way].reuse + 1, REUSE_MAX);
    } else {
        sm.blocks[way].reuse = 0;
    }

    // --- Streaming insertion ---
    if (is_streaming) {
        // Insert at LRU (oldest), unless hit (then MRU)
        if (!hit) {
            sm.blocks[way].lru = LLC_WAYS - 1;
            sm.blocks[way].reuse = 0;
        }
    } else {
        // Non-stream: protect blocks with high reuse (insert MRU)
        if (sm.blocks[way].reuse >= 2) {
            sm.blocks[way].lru = 0;
        }
    }

    // --- Update tag ---
    sm.blocks[way].tag = paddr;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print reuse and LRU distribution for first 4 sets
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << ": ";
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            std::cout << "[L:" << (int)sets[s].blocks[w].lru
                      << ",R:" << (int)sets[s].blocks[w].reuse << "] ";
        }
        std::cout << "\n";
    }
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}