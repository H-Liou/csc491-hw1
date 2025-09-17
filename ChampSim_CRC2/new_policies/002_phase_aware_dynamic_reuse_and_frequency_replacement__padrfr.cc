#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Tunable parameters ---
constexpr int REUSE_DIST_MAX = 15;
constexpr int FREQ_MAX = 15;
constexpr int PC_HISTORY_SIZE = 8;
constexpr int SPATIAL_RADIUS = 2;
constexpr int PHASE_WINDOW = 128;

// --- Replacement state per block ---
struct PADRFR_BlockState {
    uint8_t reuse_dist;      // Reuse distance counter
    uint8_t freq;            // Access frequency counter
    uint64_t last_PC;        // Last access PC
    uint64_t last_addr;      // Last access address
    uint64_t last_access;    // Timestamp of last access
};

// --- Per-set phase detection and stats ---
struct PADRFR_SetState {
    std::vector<uint64_t> pc_history; // Circular buffer of recent PCs
    uint32_t pc_hist_ptr;
    uint32_t spatial_hits;
    uint32_t temporal_hits;
    uint32_t accesses;
    enum PhaseType { PHASE_SPATIAL, PHASE_TEMPORAL, PHASE_RANDOM } phase;
};

std::vector<std::vector<PADRFR_BlockState>> block_state(LLC_SETS, std::vector<PADRFR_BlockState>(LLC_WAYS));
std::vector<PADRFR_SetState> set_state(LLC_SETS);

uint64_t global_access_count = 0;

// --- Helper: Check spatial locality ---
bool is_spatially_close(uint64_t addr1, uint64_t addr2) {
    int64_t block1 = addr1 >> 6;
    int64_t block2 = addr2 >> 6;
    return std::abs(block1 - block2) <= SPATIAL_RADIUS;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_state[set][way] = {0, 0, 0, 0, 0};
        }
        set_state[set].pc_history.resize(PC_HISTORY_SIZE, 0);
        set_state[set].pc_hist_ptr = 0;
        set_state[set].spatial_hits = 0;
        set_state[set].temporal_hits = 0;
        set_state[set].accesses = 0;
        set_state[set].phase = PADRFR_SetState::PHASE_RANDOM;
    }
    global_access_count = 0;
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
    PADRFR_SetState &ss = set_state[set];
    std::vector<int> scores(LLC_WAYS, 0);

    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        PADRFR_BlockState &bs = block_state[set][way];

        // Reuse distance: higher = less likely to be reused
        int reuse_score = bs.reuse_dist;

        // Frequency: lower = less valuable
        int freq_score = FREQ_MAX - bs.freq;

        // PC reuse: lower score if PC matches recent history
        int pc_score = 0;
        for (uint64_t recent_pc : ss.pc_history)
            if (bs.last_PC == recent_pc)
                pc_score -= 2;

        // Spatial locality: lower score if block is spatially close
        int spatial_score = is_spatially_close(bs.last_addr, paddr) ? -2 : 0;

        // Age: older blocks are less likely to be reused
        int age_score = (global_access_count - bs.last_access) > PHASE_WINDOW ? 1 : 0;

        // Phase-adaptive weighting
        int score = 0;
        if (ss.phase == PADRFR_SetState::PHASE_SPATIAL)
            score = reuse_score + 2 * spatial_score + freq_score + age_score;
        else if (ss.phase == PADRFR_SetState::PHASE_TEMPORAL)
            score = 2 * reuse_score + 2 * pc_score + freq_score + spatial_score + age_score;
        else // RANDOM
            score = reuse_score + freq_score + pc_score + spatial_score + 2 * age_score;

        scores[way] = score;
    }

    // Find block with highest score (least likely to be reused)
    int max_score = scores[0];
    uint32_t victim = 0;
    uint64_t oldest = block_state[set][0].last_access;
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (scores[way] > max_score ||
            (scores[way] == max_score && block_state[set][way].last_access < oldest)) {
            max_score = scores[way];
            victim = way;
            oldest = block_state[set][way].last_access;
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
    PADRFR_BlockState &bs = block_state[set][way];
    PADRFR_SetState &ss = set_state[set];
    global_access_count++;

    // Update block state
    bs.last_PC = PC;
    bs.last_addr = paddr;
    bs.last_access = global_access_count;

    // Reuse distance: reset on hit, increment on miss (cap at max)
    if (hit)
        bs.reuse_dist = 0;
    else if (bs.reuse_dist < REUSE_DIST_MAX)
        bs.reuse_dist++;

    // Frequency: increment on hit, decay on miss (cap at max)
    if (hit) {
        if (bs.freq < FREQ_MAX) bs.freq++;
    } else {
        if (bs.freq > 0) bs.freq--;
    }

    // --- Update PC history ---
    ss.pc_history[ss.pc_hist_ptr] = PC;
    ss.pc_hist_ptr = (ss.pc_hist_ptr + 1) % PC_HISTORY_SIZE;

    // --- Phase stats ---
    ss.accesses++;
    // Spatial hit: if any block in set is spatially close
    bool spatial_hit = false;
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        if (is_spatially_close(block_state[set][w].last_addr, paddr))
            spatial_hit = true;
    if (spatial_hit) ss.spatial_hits++;

    // Temporal hit: if any block in set has matching PC
    bool temporal_hit = false;
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        if (block_state[set][w].last_PC == PC)
            temporal_hit = true;
    if (temporal_hit) ss.temporal_hits++;

    // --- Phase classification ---
    if (ss.accesses >= PHASE_WINDOW) {
        double spatial_frac = double(ss.spatial_hits) / PHASE_WINDOW;
        double temporal_frac = double(ss.temporal_hits) / PHASE_WINDOW;
        if (spatial_frac > 0.6)
            ss.phase = PADRFR_SetState::PHASE_SPATIAL;
        else if (temporal_frac > 0.6)
            ss.phase = PADRFR_SetState::PHASE_TEMPORAL;
        else
            ss.phase = PADRFR_SetState::PHASE_RANDOM;
        ss.spatial_hits = 0;
        ss.temporal_hits = 0;
        ss.accesses = 0;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    uint32_t spatial = 0, temporal = 0, random = 0;
    for (auto &ss : set_state) {
        if (ss.phase == PADRFR_SetState::PHASE_SPATIAL) spatial++;
        else if (ss.phase == PADRFR_SetState::PHASE_TEMPORAL) temporal++;
        else random++;
    }
    std::cout << "PADRFR: Final phase distribution: "
              << "Spatial=" << spatial << ", Temporal=" << temporal << ", Random=" << random << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    uint32_t spatial = 0, temporal = 0, random = 0;
    for (auto &ss : set_state) {
        if (ss.phase == PADRFR_SetState::PHASE_SPATIAL) spatial++;
        else if (ss.phase == PADRFR_SetState::PHASE_TEMPORAL) temporal++;
        else random++;
    }
    std::cout << "PADRFR Heartbeat: "
              << "Spatial=" << spatial << ", Temporal=" << temporal << ", Random=" << random
              << ", Accesses=" << global_access_count << std::endl;
}