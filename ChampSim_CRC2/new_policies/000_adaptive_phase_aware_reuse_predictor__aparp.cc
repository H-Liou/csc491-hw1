#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Tunable parameters
constexpr int PHASE_WINDOW = 64;           // Number of accesses to consider for phase detection
constexpr int REUSE_CONFIDENCE_MAX = 7;    // Max confidence for reuse prediction
constexpr int SPATIAL_DISTANCE = 2;        // Distance threshold for spatial locality
constexpr int PC_REUSE_TABLE_SIZE = 4096;  // Entries for PC-based reuse table

// Replacement state per block
struct BlockState {
    uint64_t last_access_time;
    uint8_t reuse_confidence;   // 0-REUSE_CONFIDENCE_MAX
    uint64_t last_paddr;
    uint64_t last_PC;
};

// Phase signature per set
struct PhaseSignature {
    uint64_t last_phase_time;
    uint64_t last_PC;
    uint32_t phase_entropy;     // Simple entropy metric
    uint32_t spatial_hits;      // Count of spatial locality hits
    uint32_t temporal_hits;     // Count of temporal locality hits
    std::vector<uint64_t> recent_paddrs;
};

// PC-based reuse table (global)
struct PCReuseEntry {
    uint8_t reuse_confidence;
    uint64_t last_access_time;
};

std::vector<std::vector<BlockState>> block_state(LLC_SETS, std::vector<BlockState>(LLC_WAYS));
std::vector<PhaseSignature> phase_signature(LLC_SETS);
std::unordered_map<uint64_t, PCReuseEntry> pc_reuse_table;

// Global time counter
uint64_t global_access_counter = 0;

// Statistics
uint64_t total_evictions = 0;
uint64_t phase_switches = 0;
uint64_t spatial_evictions = 0;
uint64_t temporal_evictions = 0;
uint64_t predictive_evictions = 0;

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_state[set][way] = {0, 0, 0, 0};
        }
        phase_signature[set] = {0, 0, 0, 0, 0, std::vector<uint64_t>()};
    }
    pc_reuse_table.clear();
    global_access_counter = 0;
    total_evictions = 0;
    phase_switches = 0;
    spatial_evictions = 0;
    temporal_evictions = 0;
    predictive_evictions = 0;
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

    // --- Phase detection ---
    PhaseSignature &psig = phase_signature[set];
    if (psig.recent_paddrs.size() >= PHASE_WINDOW) {
        // Calculate simple entropy: count unique addresses
        std::unordered_map<uint64_t, int> addr_count;
        for (auto addr : psig.recent_paddrs) addr_count[addr]++;
        uint32_t entropy = addr_count.size();
        // If phase changed (entropy shifts > threshold), record
        if (abs((int)entropy - (int)psig.phase_entropy) > (PHASE_WINDOW / 4)) {
            phase_switches++;
            psig.phase_entropy = entropy;
        }
        psig.recent_paddrs.clear();
    }
    psig.recent_paddrs.push_back(paddr);

    // --- Block scoring ---
    int victim_way = -1;
    int min_score = 1000000; // Large value
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        BlockState &bs = block_state[set][way];

        // Reuse prediction (PC-based)
        uint8_t pc_reuse = 0;
        auto it = pc_reuse_table.find(bs.last_PC);
        if (it != pc_reuse_table.end())
            pc_reuse = it->second.reuse_confidence;

        // Temporal locality: recency
        int temporal_score = (int)(global_access_counter - bs.last_access_time);

        // Spatial locality: distance from last accessed address
        int spatial_score = (abs((int64_t)paddr - (int64_t)bs.last_paddr) <= (SPATIAL_DISTANCE << 6)) ? 0 : 1;

        // Final score: weighted sum (lower is better)
        int score = 0;
        // If in regular phase, emphasize spatial locality
        if (psig.phase_entropy < (PHASE_WINDOW / 2)) {
            score = spatial_score * 5 + temporal_score + (REUSE_CONFIDENCE_MAX - bs.reuse_confidence) * 3 + (REUSE_CONFIDENCE_MAX - pc_reuse) * 2;
        } else {
            // In irregular phase, emphasize reuse prediction and recency
            score = temporal_score * 2 + (REUSE_CONFIDENCE_MAX - bs.reuse_confidence) * 4 + (REUSE_CONFIDENCE_MAX - pc_reuse) * 4;
        }

        if (score < min_score) {
            min_score = score;
            victim_way = way;
        }
    }

    // Track eviction type
    if (psig.phase_entropy < (PHASE_WINDOW / 2)) spatial_evictions++;
    else if (psig.phase_entropy > (PHASE_WINDOW / 2)) temporal_evictions++;
    else predictive_evictions++;
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

    BlockState &bs = block_state[set][way];
    bs.last_access_time = global_access_counter;
    bs.last_paddr = paddr;
    bs.last_PC = PC;

    // Update reuse confidence
    if (hit) {
        if (bs.reuse_confidence < REUSE_CONFIDENCE_MAX)
            bs.reuse_confidence++;
    } else {
        if (bs.reuse_confidence > 0)
            bs.reuse_confidence--;
    }

    // Update PC-based reuse table
    auto &entry = pc_reuse_table[PC];
    entry.last_access_time = global_access_counter;
    if (hit) {
        if (entry.reuse_confidence < REUSE_CONFIDENCE_MAX)
            entry.reuse_confidence++;
    } else {
        if (entry.reuse_confidence > 0)
            entry.reuse_confidence--;
    }
    // Limit table size
    if (pc_reuse_table.size() > PC_REUSE_TABLE_SIZE) {
        // Remove oldest entry
        uint64_t oldest_PC = 0;
        uint64_t oldest_time = global_access_counter;
        for (auto &kv : pc_reuse_table) {
            if (kv.second.last_access_time < oldest_time) {
                oldest_time = kv.second.last_access_time;
                oldest_PC = kv.first;
            }
        }
        pc_reuse_table.erase(oldest_PC);
    }
}

void PrintStats() {
    std::cout << "APARP: total_evictions=" << total_evictions
              << " phase_switches=" << phase_switches
              << " spatial_evictions=" << spatial_evictions
              << " temporal_evictions=" << temporal_evictions
              << " predictive_evictions=" << predictive_evictions
              << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}