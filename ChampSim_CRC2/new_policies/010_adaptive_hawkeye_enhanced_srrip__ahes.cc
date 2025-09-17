#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int RRIP_BITS = 2;
constexpr int RRIP_MAX = (1 << RRIP_BITS) - 1; // 3
constexpr int RRIP_LONG = RRIP_MAX; // Insert with 3 for cache-averse
constexpr int RRIP_SHORT = 0;       // Insert with 0 for cache-friendly

// Hawkeye-like PC-based reuse prediction
constexpr int PC_TABLE_SIZE = 4096;
constexpr int PC_COUNTER_BITS = 2;
constexpr int PC_COUNTER_MAX = (1 << PC_COUNTER_BITS) - 1;
constexpr int PC_COUNTER_MIN = 0;
constexpr int PC_FRIENDLY_THRESHOLD = 2; // >=2 is cache-friendly

struct LineState {
    uint64_t tag = 0;
    uint8_t rrip = RRIP_MAX;
    bool valid = false;
    uint64_t PC = 0;
};

struct SetState {
    std::vector<LineState> lines;
};

std::vector<SetState> sets(LLC_SETS);

// PC-based reuse table (Hawkeye-style)
struct PCEntry {
    uint8_t reuse_counter = PC_COUNTER_MIN;
};

std::unordered_map<uint64_t, PCEntry> pc_table;

uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;

void InitReplacementState() {
    for (auto& set : sets) {
        set.lines.resize(LLC_WAYS);
        for (auto& line : set.lines) {
            line.tag = 0;
            line.rrip = RRIP_MAX;
            line.valid = false;
            line.PC = 0;
        }
    }
    pc_table.clear();
    total_hits = total_misses = total_evictions = 0;
}

// Find victim using SRRIP (prefer invalid, else highest RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState& s = sets[set];
    // 1. Prefer invalid lines
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!s.lines[way].valid)
            return way;
    }
    // 2. SRRIP: Find line with RRIP_MAX
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.lines[way].rrip == RRIP_MAX)
                return way;
        }
        // Increment RRIP of all lines (aging)
        for (auto& line : s.lines)
            if (line.rrip < RRIP_MAX) line.rrip++;
    }
}

// Update PC reuse table on eviction
void UpdatePCReuseOnEviction(uint64_t evicted_PC, bool was_hit) {
    // Only track up to PC_TABLE_SIZE entries
    if (pc_table.size() > PC_TABLE_SIZE) {
        // Remove random entry (simple way to keep table bounded)
        auto it = pc_table.begin();
        std::advance(it, rand() % pc_table.size());
        pc_table.erase(it);
    }
    auto& entry = pc_table[evicted_PC];
    if (was_hit) {
        if (entry.reuse_counter < PC_COUNTER_MAX)
            entry.reuse_counter++;
    } else {
        if (entry.reuse_counter > PC_COUNTER_MIN)
            entry.reuse_counter--;
    }
}

// Update replacement state after access
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
    LineState& line = s.lines[way];
    uint64_t line_addr = paddr >> 6;

    if (hit) total_hits++;
    else { total_misses++; total_evictions++; }

    // On hit: promote line (set RRIP to 0)
    if (hit) {
        line.rrip = RRIP_SHORT;
        line.tag = line_addr;
        line.valid = true;
        line.PC = PC;
        return;
    }

    // On miss: adaptive insertion based on PC reuse history
    // 1. Update PC reuse table for evicted line
    if (line.valid) {
        // If the evicted line was hit recently, mark its PC as cache-friendly
        UpdatePCReuseOnEviction(line.PC, line.rrip == RRIP_SHORT);
    }

    // 2. Insert new line with RRIP based on PC table
    auto it = pc_table.find(PC);
    if (it != pc_table.end() && it->second.reuse_counter >= PC_FRIENDLY_THRESHOLD) {
        // Cache-friendly PC: retain longer
        line.rrip = RRIP_SHORT;
    } else {
        // Cache-averse PC: evict quickly
        line.rrip = RRIP_LONG;
    }
    line.tag = line_addr;
    line.valid = true;
    line.PC = PC;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "AHES: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}