#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRSD parameters
#define REUSE_WINDOW 8         // Number of accesses to track per set
#define STREAM_STRIDE_THRESH 4 // Minimum stride to consider as streaming
#define STREAM_CONFIDENCE 6    // Number of sequential accesses to trigger streaming mode

struct AccessHistoryEntry {
    uint64_t tag;
    uint64_t last_addr;
    uint64_t last_pc;
    uint32_t reuse_count;
};

struct SetState {
    // LRU stack: way 0 = MRU, way LLC_WAYS-1 = LRU
    std::vector<uint8_t> lru_stack;
    // Recent access history for reuse detection
    std::vector<AccessHistoryEntry> history;
    // Streaming detection
    uint64_t last_addr;
    uint32_t stream_seq_count;
    bool streaming_mode;
};

std::vector<SetState> sets(LLC_SETS);

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].lru_stack.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            sets[s].lru_stack[w] = w;
        sets[s].history.clear();
        sets[s].last_addr = 0;
        sets[s].stream_seq_count = 0;
        sets[s].streaming_mode = false;
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
    SetState &ss = sets[set];

    // If streaming detected, evict LRU (last in stack)
    if (ss.streaming_mode) {
        return ss.lru_stack[LLC_WAYS - 1];
    }

    // Otherwise, prefer to evict blocks with lowest reuse count in history
    uint32_t victim = ss.lru_stack[LLC_WAYS - 1];
    uint32_t min_reuse = UINT32_MAX;
    uint32_t min_way = victim;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        uint64_t tag = current_set[w].tag;
        auto it = std::find_if(ss.history.begin(), ss.history.end(),
            [tag](const AccessHistoryEntry& e){ return e.tag == tag; });
        uint32_t reuse = (it != ss.history.end()) ? it->reuse_count : 0;
        if (reuse < min_reuse) {
            min_reuse = reuse;
            min_way = w;
        }
    }
    return min_way;
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
    SetState &ss = sets[set];
    uint64_t tag = (paddr >> 6) & 0xFFFFFFFFFFFF; // 64B blocks

    // --- Update access history for reuse detection ---
    auto it = std::find_if(ss.history.begin(), ss.history.end(),
        [tag](const AccessHistoryEntry& e){ return e.tag == tag; });
    if (hit) {
        // Promote to MRU in LRU stack
        auto pos = std::find(ss.lru_stack.begin(), ss.lru_stack.end(), way);
        if (pos != ss.lru_stack.end()) {
            ss.lru_stack.erase(pos);
            ss.lru_stack.insert(ss.lru_stack.begin(), way);
        }
        // Update reuse count
        if (it != ss.history.end())
            it->reuse_count++;
        else {
            if (ss.history.size() >= REUSE_WINDOW)
                ss.history.erase(ss.history.begin());
            ss.history.push_back({tag, paddr, PC, 1});
        }
    } else {
        // Insert block: if high reuse, insert as MRU; else, as LRU
        uint32_t reuse = (it != ss.history.end()) ? it->reuse_count : 0;
        auto pos = std::find(ss.lru_stack.begin(), ss.lru_stack.end(), way);
        if (pos != ss.lru_stack.end())
            ss.lru_stack.erase(pos);

        if (reuse >= 2) {
            // High reuse, insert as MRU
            ss.lru_stack.insert(ss.lru_stack.begin(), way);
        } else {
            // Low reuse, insert as LRU
            ss.lru_stack.push_back(way);
        }

        // Update history
        if (it != ss.history.end()) {
            it->reuse_count = 0;
            it->last_addr = paddr;
            it->last_pc = PC;
        } else {
            if (ss.history.size() >= REUSE_WINDOW)
                ss.history.erase(ss.history.begin());
            ss.history.push_back({tag, paddr, PC, 0});
        }
    }

    // --- Streaming/pointer-chase detection ---
    uint64_t stride = (ss.last_addr > 0) ? std::abs((int64_t)paddr - (int64_t)ss.last_addr) : 0;
    if (stride >= (STREAM_STRIDE_THRESH * 64)) {
        ss.stream_seq_count++;
        if (ss.stream_seq_count >= STREAM_CONFIDENCE)
            ss.streaming_mode = true;
    } else {
        ss.stream_seq_count = 0;
        ss.streaming_mode = false;
    }
    ss.last_addr = paddr;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print stats for first 4 sets
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " history:\n";
        for (auto &e : sets[s].history) {
            std::cout << "Tag=" << std::hex << e.tag << std::dec
                      << " reuse=" << e.reuse_count << " last_addr=" << e.last_addr
                      << " last_pc=" << e.last_pc << "\n";
        }
        std::cout << "Streaming mode: " << sets[s].streaming_mode << "\n";
    }
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op for now
}