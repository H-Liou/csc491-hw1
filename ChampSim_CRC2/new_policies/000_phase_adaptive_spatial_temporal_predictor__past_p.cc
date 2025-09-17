#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Tunable parameters ---
constexpr int PHASE_WINDOW = 128;         // Number of accesses to consider for phase detection
constexpr int REUSE_COUNTER_MAX = 7;      // Max value for reuse counters
constexpr int SPATIAL_CLUSTER_RADIUS = 4; // Number of adjacent blocks considered "spatially close"
constexpr int PHASE_CHANGE_THRESHOLD = 0.25; // Fractional change in spatial/temporal locality to trigger phase switch

// --- Replacement state per block ---
struct PA_BlockState {
    uint8_t reuse_counter;    // Temporal reuse score
    uint8_t spatial_score;    // Spatial locality score
    uint64_t last_PC;         // Last access PC
    uint64_t last_addr;       // Last access address
    uint64_t last_access;     // Timestamp of last access
};

std::vector<std::vector<PA_BlockState>> pa_state(LLC_SETS, std::vector<PA_BlockState>(LLC_WAYS));

// --- Phase detection state ---
enum PhaseType { PHASE_REGULAR, PHASE_IRREGULAR };
PhaseType current_phase = PHASE_REGULAR;
uint64_t global_access_count = 0;

// --- Statistics for phase detection ---
struct PhaseStats {
    uint64_t spatial_hits;
    uint64_t temporal_hits;
    uint64_t accesses;
};
PhaseStats phase_stats = {0, 0, 0};

// --- Helper: Check spatial locality ---
bool is_spatially_close(uint64_t addr1, uint64_t addr2) {
    // Assume block size is 64B, so block address = addr >> 6
    int64_t block1 = addr1 >> 6;
    int64_t block2 = addr2 >> 6;
    return std::abs(block1 - block2) <= SPATIAL_CLUSTER_RADIUS;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            pa_state[set][way] = {0, 0, 0, 0, 0};
        }
    }
    current_phase = PHASE_REGULAR;
    global_access_count = 0;
    phase_stats = {0, 0, 0};
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
    // Score each block: higher score = more likely to be reused, so evict lowest
    std::vector<int> scores(LLC_WAYS, 0);

    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        PA_BlockState &bs = pa_state[set][way];

        // Temporal reuse: higher counter = more reuse
        int temporal = bs.reuse_counter;

        // Spatial locality: higher score if block is close to current address
        int spatial = is_spatially_close(bs.last_addr, paddr) ? bs.spatial_score : 0;

        // Age penalty: older blocks are less likely to be reused
        int age = (global_access_count - bs.last_access) > PHASE_WINDOW ? -2 : 0;

        // Phase-adaptive weighting
        int score = 0;
        if (current_phase == PHASE_REGULAR) {
            score = 2 * spatial + temporal + age;
        } else {
            score = 2 * temporal + spatial + age;
        }
        scores[way] = score;
    }

    // Find block with lowest score (ties: oldest)
    int min_score = scores[0];
    uint32_t victim = 0;
    uint64_t oldest = pa_state[set][0].last_access;
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (scores[way] < min_score ||
            (scores[way] == min_score && pa_state[set][way].last_access < oldest)) {
            min_score = scores[way];
            victim = way;
            oldest = pa_state[set][way].last_access;
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
    PA_BlockState &bs = pa_state[set][way];
    global_access_count++;

    // Update block state
    bs.last_PC = PC;
    bs.last_addr = paddr;
    bs.last_access = global_access_count;

    // Temporal reuse: increment if hit, decay if miss
    if (hit) {
        if (bs.reuse_counter < REUSE_COUNTER_MAX)
            bs.reuse_counter++;
        phase_stats.temporal_hits++;
    } else {
        if (bs.reuse_counter > 0)
            bs.reuse_counter--;
    }

    // Spatial locality: increment if spatially close to previous access
    if (is_spatially_close(bs.last_addr, paddr)) {
        if (bs.spatial_score < REUSE_COUNTER_MAX)
            bs.spatial_score++;
        phase_stats.spatial_hits++;
    } else {
        if (bs.spatial_score > 0)
            bs.spatial_score--;
    }

    phase_stats.accesses++;

    // --- Phase detection ---
    if (phase_stats.accesses >= PHASE_WINDOW) {
        double spatial_frac = double(phase_stats.spatial_hits) / PHASE_WINDOW;
        double temporal_frac = double(phase_stats.temporal_hits) / PHASE_WINDOW;

        // If spatial locality dominates, switch to regular; else irregular
        if (spatial_frac > temporal_frac + PHASE_CHANGE_THRESHOLD)
            current_phase = PHASE_REGULAR;
        else if (temporal_frac > spatial_frac + PHASE_CHANGE_THRESHOLD)
            current_phase = PHASE_IRREGULAR;
        // else, keep current phase

        // Reset stats for next window
        phase_stats = {0, 0, 0};
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "PAST-P: Final Phase = " << (current_phase == PHASE_REGULAR ? "REGULAR" : "IRREGULAR") << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    std::cout << "PAST-P Heartbeat: Phase = " << (current_phase == PHASE_REGULAR ? "REGULAR" : "IRREGULAR")
              << ", Accesses = " << global_access_count << std::endl;
}