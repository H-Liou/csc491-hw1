#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Policy parameters ---
#define REUSE_MAX 7
#define SPATIAL_WINDOW 8
#define PHASE_STREAM_THRESHOLD 6
#define PHASE_IRREGULAR_THRESHOLD 3

struct BlockMeta {
    uint64_t tag;
    uint8_t lru;        // LRU stack position (0 = MRU)
    uint8_t reuse;      // Reuse counter
    bool spatial;       // Recently accessed with spatial locality
};

struct SetMeta {
    std::vector<BlockMeta> blocks;
    std::vector<uint64_t> addr_hist; // For spatial locality detection
    int streaming_phase; // 0: unknown, 1: streaming, 2: irregular
};

std::vector<SetMeta> sets(LLC_SETS);

// Helper: check for spatial locality in recent accesses
bool detect_spatial(uint64_t paddr, const std::vector<uint64_t>& hist) {
    if (hist.empty()) return false;
    for (auto addr : hist) {
        // If within 128 bytes (2 cache lines), consider spatial
        if (std::abs((int64_t)paddr - (int64_t)addr) <= 128)
            return true;
    }
    return false;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].tag = 0;
            sets[s].blocks[w].lru = w;
            sets[s].blocks[w].reuse = 0;
            sets[s].blocks[w].spatial = false;
        }
        sets[s].addr_hist.clear();
        sets[s].streaming_phase = 0; // unknown
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
    SetMeta &sm = sets[set];

    // Phase detection: count spatial vs. non-spatial accesses in window
    int spatial_cnt = 0, nonspatial_cnt = 0;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (sm.blocks[w].spatial) spatial_cnt++;
        else nonspatial_cnt++;
    }

    // Streaming phase: most blocks are non-spatial
    if (nonspatial_cnt >= PHASE_STREAM_THRESHOLD)
        sm.streaming_phase = 1;
    // Irregular/pointer phase: some blocks show reuse or spatial
    else if (spatial_cnt >= PHASE_IRREGULAR_THRESHOLD)
        sm.streaming_phase = 2;
    else
        sm.streaming_phase = 0;

    // --- Victim selection ---
    uint32_t victim = LLC_WAYS;
    uint8_t min_reuse = 255;
    uint8_t max_lru = 0;

    // In streaming phase: evict block with lowest reuse, not spatial, and oldest
    if (sm.streaming_phase == 1) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (!sm.blocks[w].spatial && sm.blocks[w].reuse <= 1 && sm.blocks[w].lru >= max_lru) {
                victim = w;
                max_lru = sm.blocks[w].lru;
            }
        }
    }
    // In irregular phase: evict block with lowest reuse, even if spatial
    else if (sm.streaming_phase == 2) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (sm.blocks[w].reuse < min_reuse || (sm.blocks[w].reuse == min_reuse && sm.blocks[w].lru > max_lru)) {
                victim = w;
                min_reuse = sm.blocks[w].reuse;
                max_lru = sm.blocks[w].lru;
            }
        }
    }
    // Unknown phase: fallback to classic LRU
    if (victim == LLC_WAYS) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (sm.blocks[w].lru == (LLC_WAYS - 1))
                return w;
        }
        return 0;
    }
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
    SetMeta &sm = sets[set];

    // Update address history for spatial locality detection
    sm.addr_hist.push_back(paddr);
    if (sm.addr_hist.size() > SPATIAL_WINDOW)
        sm.addr_hist.erase(sm.addr_hist.begin());

    // Detect spatial locality for current block
    bool spatial = detect_spatial(paddr, sm.addr_hist);

    // Update block meta
    uint8_t old_lru = sm.blocks[way].lru;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (sm.blocks[w].lru < old_lru)
            sm.blocks[w].lru++;
    }
    sm.blocks[way].lru = 0;

    // Update reuse counter
    if (hit) {
        sm.blocks[way].reuse = std::min<uint8_t>(sm.blocks[way].reuse + 1, REUSE_MAX);
    } else {
        sm.blocks[way].reuse = 0;
    }

    // Update spatial flag
    sm.blocks[way].spatial = spatial;

    // Phase-adaptive insertion
    if (sm.streaming_phase == 1) {
        // Streaming: insert at LRU unless hit
        if (!hit) {
            sm.blocks[way].lru = LLC_WAYS - 1;
            sm.blocks[way].reuse = 0;
        }
    } else if (sm.streaming_phase == 2) {
        // Irregular: protect blocks with reuse >=2 (insert MRU)
        if (sm.blocks[way].reuse >= 2)
            sm.blocks[way].lru = 0;
    }

    // Update tag
    sm.blocks[way].tag = paddr;
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    // Print LRU and reuse for first 4 sets
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << ": ";
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            std::cout << "[L:" << (int)sets[s].blocks[w].lru
                      << ",R:" << (int)sets[s].blocks[w].reuse
                      << ",S:" << (int)sets[s].blocks[w].spatial << "] ";
        }
        std::cout << "\n";
    }
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    // No-op
}