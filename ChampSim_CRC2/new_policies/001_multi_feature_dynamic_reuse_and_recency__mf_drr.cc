#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int PC_TABLE_SIZE = 2048;
constexpr int RECENT_ADDRS = 8;

// Replacement state per block
struct BlockState {
    uint64_t last_access_time;
    uint32_t hit_count;
    uint64_t last_PC;
    uint64_t last_addr;
};

// PC reuse table (global)
struct PCReuseEntry {
    uint32_t reuse_score; // higher = more reuse
    uint64_t last_access_time;
};

// Per-set spatial locality history
struct SetHistory {
    std::vector<uint64_t> recent_addrs;
};

std::vector<std::vector<BlockState>> block_state(LLC_SETS, std::vector<BlockState>(LLC_WAYS));
std::unordered_map<uint64_t, PCReuseEntry> pc_reuse_table;
std::vector<SetHistory> set_history(LLC_SETS);

uint64_t global_access_counter = 0;

// Stats
uint64_t total_evictions = 0;
uint64_t freq_evictions = 0;
uint64_t recency_evictions = 0;
uint64_t spatial_evictions = 0;
uint64_t pc_evictions = 0;

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_state[set][way] = {0, 0, 0, 0};
        }
        set_history[set].recent_addrs.clear();
    }
    pc_reuse_table.clear();
    global_access_counter = 0;
    total_evictions = 0;
    freq_evictions = 0;
    recency_evictions = 0;
    spatial_evictions = 0;
    pc_evictions = 0;
}

// Returns minimum distance to recent addresses, or large value if none
int spatial_distance(uint64_t paddr, const std::vector<uint64_t>& recent_addrs) {
    int min_dist = 0x7fffffff;
    for (auto addr : recent_addrs) {
        int dist = std::abs((int64_t)paddr - (int64_t)addr);
        if (dist < min_dist) min_dist = dist;
    }
    return min_dist;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    global_access_counter++;

    // Update recent address history for spatial locality
    auto& history = set_history[set].recent_addrs;
    if (history.size() >= RECENT_ADDRS)
        history.erase(history.begin());
    history.push_back(paddr);

    int victim_way = 0;
    int min_score = 0x7fffffff;

    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        BlockState& bs = block_state[set][way];

        // Recency: older blocks are more likely victims
        int recency_score = (int)(global_access_counter - bs.last_access_time);

        // Frequency: blocks with fewer hits are more likely victims
        int freq_score = (int)(bs.hit_count);

        // Spatial locality: blocks far from recent addresses are more likely victims
        int spatial_score = spatial_distance(bs.last_addr, history) / 64; // cacheline granularity

        // PC-based reuse: blocks with PCs with low reuse are more likely victims
        int pc_score = 0;
        auto it = pc_reuse_table.find(bs.last_PC);
        if (it != pc_reuse_table.end())
            pc_score = 10 - std::min(it->second.reuse_score, 10u); // invert: low reuse_score => high victim score
        else
            pc_score = 10; // unknown PC, penalize

        // Weighted sum: tune weights for balance
        int score = recency_score * 2 + (10 - freq_score) * 3 + spatial_score * 2 + pc_score * 3;

        if (score < min_score) {
            min_score = score;
            victim_way = way;
        }
    }

    // Track which feature dominated
    if (min_score < 40) recency_evictions++;
    else if (min_score < 80) freq_evictions++;
    else if (min_score < 120) spatial_evictions++;
    else pc_evictions++;
    total_evictions++;

    return victim_way;
}

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
    bs.last_access_time = global_access_counter;
    bs.last_addr = paddr;
    bs.last_PC = PC;
    if (hit)
        bs.hit_count = std::min(bs.hit_count + 1, 10u);
    else
        bs.hit_count = std::max(bs.hit_count - 1, 0u);

    // Update PC reuse table
    auto& entry = pc_reuse_table[PC];
    entry.last_access_time = global_access_counter;
    if (hit)
        entry.reuse_score = std::min(entry.reuse_score + 1, 10u);
    else if (entry.reuse_score > 0)
        entry.reuse_score--;

    // Limit PC table size
    if (pc_reuse_table.size() > PC_TABLE_SIZE) {
        // Remove oldest entry
        uint64_t oldest_PC = 0;
        uint64_t oldest_time = global_access_counter;
        for (auto& kv : pc_reuse_table) {
            if (kv.second.last_access_time < oldest_time) {
                oldest_time = kv.second.last_access_time;
                oldest_PC = kv.first;
            }
        }
        pc_reuse_table.erase(oldest_PC);
    }
}

void PrintStats() {
    std::cout << "MF-DRR: total_evictions=" << total_evictions
              << " freq_evictions=" << freq_evictions
              << " recency_evictions=" << recency_evictions
              << " spatial_evictions=" << spatial_evictions
              << " pc_evictions=" << pc_evictions
              << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}