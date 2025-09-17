#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRIP_MAX 3          // 2-bit RRIP
#define INSERT_RRIP_REG 1   // Insert priority for regular
#define INSERT_RRIP_IRR 3   // Insert priority for irregular
#define PROMOTE_RRIP 0      // Promote to MRU on hit

// Pointer-chase detection
#define PC_TRACK_SIZE 8     // Track last N miss PCs per set
#define PC_CHASE_THRESH 5   // If >T misses from same PC, treat as pointer-chase

struct BlockState {
    uint8_t rrip;
};

struct SetState {
    std::vector<BlockState> blocks;
    std::unordered_map<uint64_t, uint32_t> miss_pc_count; // PC -> count
    std::vector<uint64_t> recent_miss_pcs; // FIFO of last N miss PCs
    bool pointer_chase_mode;
};

std::vector<SetState> sets(LLC_SETS);

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            sets[s].blocks[w].rrip = RRIP_MAX;
        sets[s].miss_pc_count.clear();
        sets[s].recent_miss_pcs.clear();
        sets[s].pointer_chase_mode = false;
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

    // Prefer victim with RRIP==RRIP_MAX
    for (uint32_t loop = 0; loop < 2; ++loop) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ss.blocks[w].rrip == RRIP_MAX)
                return w;
        }
        // If none found, increment RRIP counters
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (ss.blocks[w].rrip < RRIP_MAX)
                ss.blocks[w].rrip++;
    }
    // Fallback (shouldn't happen)
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
    SetState &ss = sets[set];

    // --- Pointer-chase detection ---
    if (!hit) {
        // Track miss PC
        ss.miss_pc_count[PC]++;
        ss.recent_miss_pcs.push_back(PC);
        if (ss.recent_miss_pcs.size() > PC_TRACK_SIZE) {
            uint64_t old_pc = ss.recent_miss_pcs.front();
            ss.recent_miss_pcs.erase(ss.recent_miss_pcs.begin());
            // Decrement count for old PC
            if (ss.miss_pc_count[old_pc] > 0)
                ss.miss_pc_count[old_pc]--;
        }
        // If any PC exceeds threshold, enable pointer-chase mode
        ss.pointer_chase_mode = false;
        for (auto &kv : ss.miss_pc_count) {
            if (kv.second >= PC_CHASE_THRESH) {
                ss.pointer_chase_mode = true;
                break;
            }
        }
    }

    // --- RRIP update ---
    if (hit) {
        // Promote block to MRU (lowest RRIP)
        ss.blocks[way].rrip = PROMOTE_RRIP;
    } else {
        // Insert block: if pointer-chase detected, use high RRIP (low priority)
        if (ss.pointer_chase_mode)
            ss.blocks[way].rrip = INSERT_RRIP_IRR;
        else
            ss.blocks[way].rrip = INSERT_RRIP_REG;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print pointer-chase mode for first 4 sets
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " pointer_chase_mode: " << sets[s].pointer_chase_mode << "\n";
        std::cout << "Miss PC counts: ";
        for (auto &kv : sets[s].miss_pc_count)
            std::cout << std::hex << kv.first << std::dec << ":" << kv.second << " ";
        std::cout << "\n";
    }
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}