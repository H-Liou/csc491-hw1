#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Tunable parameters ---
constexpr int PC_HISTORY_SIZE = 8;
constexpr int ADDR_HISTORY_SIZE = 8;
constexpr int PHASE_WINDOW = 128; // Number of accesses to consider for phase detection
constexpr int SPATIAL_RADIUS = 2;

// --- Replacement state per block ---
struct PAMSR_BlockState {
    uint64_t last_access;    // Timestamp of last access (recency)
    uint64_t last_PC;        // Last access PC
    uint64_t last_addr;      // Last access address
};

// --- Per-set history for PC and address correlation ---
struct PAMSR_SetState {
    std::vector<uint64_t> pc_history;    // Circular buffer of recent PCs
    std::vector<uint64_t> addr_history;  // Circular buffer of recent addresses
    uint32_t pc_hist_ptr;
    uint32_t addr_hist_ptr;

    // Phase detection counters
    uint32_t spatial_hits;
    uint32_t pc_hits;
    uint32_t access_count;
    bool spatial_phase; // true: spatial, false: pointer/control
};

std::vector<std::vector<PAMSR_BlockState>> block_state(LLC_SETS, std::vector<PAMSR_BlockState>(LLC_WAYS));
std::vector<PAMSR_SetState> set_state(LLC_SETS);

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
            block_state[set][way] = {0, 0, 0};
        }
        set_state[set].pc_history.resize(PC_HISTORY_SIZE, 0);
        set_state[set].addr_history.resize(ADDR_HISTORY_SIZE, 0);
        set_state[set].pc_hist_ptr = 0;
        set_state[set].addr_hist_ptr = 0;
        set_state[set].spatial_hits = 0;
        set_state[set].pc_hits = 0;
        set_state[set].access_count = 0;
        set_state[set].spatial_phase = true; // default to spatial
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
    PAMSR_SetState &ss = set_state[set];
    std::vector<int> scores(LLC_WAYS, 0);

    // Phase weights
    int spatial_weight = ss.spatial_phase ? 8 : 2;
    int pc_weight = ss.spatial_phase ? 2 : 8;

    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        PAMSR_BlockState &bs = block_state[set][way];

        // Recency: older blocks are less valuable
        int recency_score = (global_access_count - bs.last_access);

        // PC correlation: penalize blocks that match recent PC history
        int pc_score = 0;
        for (uint64_t recent_pc : ss.pc_history)
            if (bs.last_PC == recent_pc)
                pc_score -= pc_weight;

        // Spatial locality: penalize blocks that are spatially close to recent addresses
        int spatial_score = 0;
        for (uint64_t recent_addr : ss.addr_history)
            if (is_spatially_close(bs.last_addr, recent_addr))
                spatial_score -= spatial_weight;

        // Combine scores: prioritize high recency, low PC/spatial correlation
        scores[way] = recency_score + pc_score + spatial_score;
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
    PAMSR_BlockState &bs = block_state[set][way];
    PAMSR_SetState &ss = set_state[set];
    global_access_count++;

    // Update block state
    bs.last_PC = PC;
    bs.last_addr = paddr;
    bs.last_access = global_access_count;

    // Update PC history
    ss.pc_history[ss.pc_hist_ptr] = PC;
    ss.pc_hist_ptr = (ss.pc_hist_ptr + 1) % PC_HISTORY_SIZE;

    // Update address history
    ss.addr_history[ss.addr_hist_ptr] = paddr;
    ss.addr_hist_ptr = (ss.addr_hist_ptr + 1) % ADDR_HISTORY_SIZE;

    // --- Phase detection ---
    ss.access_count++;
    bool spatial_hit = false, pc_hit = false;
    for (uint64_t recent_addr : ss.addr_history)
        if (is_spatially_close(paddr, recent_addr))
            spatial_hit = true;
    for (uint64_t recent_pc : ss.pc_history)
        if (PC == recent_pc)
            pc_hit = true;
    if (spatial_hit) ss.spatial_hits++;
    if (pc_hit) ss.pc_hits++;

    if (ss.access_count >= PHASE_WINDOW) {
        // If spatial hits dominate, switch to spatial phase
        ss.spatial_phase = (ss.spatial_hits >= ss.pc_hits);
        ss.spatial_hits = 0;
        ss.pc_hits = 0;
        ss.access_count = 0;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    uint32_t spatial_sets = 0, pointer_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set_state[set].spatial_phase) spatial_sets++;
        else pointer_sets++;
    }
    std::cout << "PAMSR: Sets in spatial phase: " << spatial_sets
              << ", pointer/control phase: " << pointer_sets << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    std::cout << "PAMSR Heartbeat: Accesses=" << global_access_count << std::endl;
}