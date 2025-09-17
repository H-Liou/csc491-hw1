#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_LONG 0
#define RRIP_SHORT RRIP_MAX

// Reuse tracking
#define REUSE_TABLE_SIZE 4 // Recent addresses per set
#define STREAM_WINDOW 16   // Window for streaming detection
#define STREAM_THRESHOLD 12 // If >12/16 recent accesses are misses, treat as streaming

struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
    uint64_t last_pc;
};

struct SetState {
    std::vector<BlockMeta> meta;
    std::vector<uint64_t> reuse_table; // Recent block tags
    std::vector<uint64_t> pc_table;    // Recent PCs
    std::vector<uint8_t> stream_window; // 1 = miss, 0 = hit
    uint8_t stream_ptr;
    bool streaming_mode;
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0, 0});
        set.reuse_table.assign(REUSE_TABLE_SIZE, 0);
        set.pc_table.assign(REUSE_TABLE_SIZE, 0);
        set.stream_window.assign(STREAM_WINDOW, 0);
        set.stream_ptr = 0;
        set.streaming_mode = false;
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

    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }

    // In streaming mode: evict RRIP_MAX block (dead-on-arrival)
    if (s.streaming_mode) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip == RRIP_MAX)
                return way;
        }
        // If none, evict block with maximal RRIP
        uint32_t victim = 0;
        uint8_t max_rrip = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip >= max_rrip) {
                max_rrip = s.meta[way].rrip;
                victim = way;
            }
        }
        return victim;
    }

    // In reuse mode: evict RRIP_MAX block with least recent PC
    uint32_t victim = 0;
    uint8_t max_rrip = 0;
    uint64_t oldest_pc = UINT64_MAX;
    bool found = false;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.meta[way].rrip == RRIP_MAX) {
            if (!found || s.meta[way].last_pc < oldest_pc) {
                victim = way;
                oldest_pc = s.meta[way].last_pc;
                found = true;
            }
        }
    }
    if (found)
        return victim;

    // Aging: increment RRIP for all blocks
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        s.meta[way].rrip = std::min<uint8_t>(RRIP_MAX, s.meta[way].rrip + 1);
    }

    // Fallback: evict block with maximal RRIP value
    victim = 0;
    max_rrip = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.meta[way].rrip >= max_rrip) {
            max_rrip = s.meta[way].rrip;
            victim = way;
        }
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
    SetState& s = sets[set];
    uint64_t tag = paddr >> 6;

    // --- Streaming detection ---
    s.stream_window[s.stream_ptr] = hit ? 0 : 1;
    s.stream_ptr = (s.stream_ptr + 1) % STREAM_WINDOW;

    uint8_t miss_count = 0;
    for (auto v : s.stream_window) miss_count += v;
    bool prev_mode = s.streaming_mode;
    s.streaming_mode = (miss_count >= STREAM_THRESHOLD);

    // --- Update reuse table and PC table ---
    auto addr_it = std::find(s.reuse_table.begin(), s.reuse_table.end(), tag);
    auto pc_it = std::find(s.pc_table.begin(), s.pc_table.end(), PC);

    if (hit) {
        // On hit: reset RRIP, update PC
        s.meta[way].rrip = RRIP_LONG;
        s.meta[way].last_pc = PC;
        // Promote to front of reuse table
        if (addr_it != s.reuse_table.end()) {
            s.reuse_table.erase(addr_it);
        }
        s.reuse_table.insert(s.reuse_table.begin(), tag);
        if (s.reuse_table.size() > REUSE_TABLE_SIZE)
            s.reuse_table.pop_back();
        // Promote to front of PC table
        if (pc_it != s.pc_table.end()) {
            s.pc_table.erase(pc_it);
        }
        s.pc_table.insert(s.pc_table.begin(), PC);
        if (s.pc_table.size() > REUSE_TABLE_SIZE)
            s.pc_table.pop_back();
    } else {
        // On miss/insertion
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].last_pc = PC;
        // Insert RRIP: streaming mode = short retention, reuse mode = long retention if tag/PC seen recently
        uint8_t insert_rrip = RRIP_SHORT;
        if (!s.streaming_mode) {
            bool reuse_addr = (std::find(s.reuse_table.begin(), s.reuse_table.end(), tag) != s.reuse_table.end());
            bool reuse_pc = (std::find(s.pc_table.begin(), s.pc_table.end(), PC) != s.pc_table.end());
            if (reuse_addr || reuse_pc)
                insert_rrip = RRIP_LONG;
        }
        s.meta[way].rrip = insert_rrip;
        // Update reuse table and PC table
        if (addr_it != s.reuse_table.end()) {
            s.reuse_table.erase(addr_it);
        }
        s.reuse_table.insert(s.reuse_table.begin(), tag);
        if (s.reuse_table.size() > REUSE_TABLE_SIZE)
            s.reuse_table.pop_back();
        if (pc_it != s.pc_table.end()) {
            s.pc_table.erase(pc_it);
        }
        s.pc_table.insert(s.pc_table.begin(), PC);
        if (s.pc_table.size() > REUSE_TABLE_SIZE)
            s.pc_table.pop_back();
    }
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "PADRSD: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}