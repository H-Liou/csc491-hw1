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
constexpr int SPATIAL_RADIUS = 2;

// --- Replacement state per block ---
struct MSARPSC_BlockState {
    uint64_t last_access;    // Timestamp of last access (recency)
    uint64_t last_PC;        // Last access PC
    uint64_t last_addr;      // Last access address
};

// --- Per-set history for PC and address correlation ---
struct MSARPSC_SetState {
    std::vector<uint64_t> pc_history;    // Circular buffer of recent PCs
    std::vector<uint64_t> addr_history;  // Circular buffer of recent addresses
    uint32_t pc_hist_ptr;
    uint32_t addr_hist_ptr;
};

std::vector<std::vector<MSARPSC_BlockState>> block_state(LLC_SETS, std::vector<MSARPSC_BlockState>(LLC_WAYS));
std::vector<MSARPSC_SetState> set_state(LLC_SETS);

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
    MSARPSC_SetState &ss = set_state[set];
    std::vector<int> scores(LLC_WAYS, 0);

    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        MSARPSC_BlockState &bs = block_state[set][way];

        // Recency: older blocks are less valuable
        int recency_score = (global_access_count - bs.last_access);

        // PC correlation: penalize blocks that match recent PC history
        int pc_score = 0;
        for (uint64_t recent_pc : ss.pc_history)
            if (bs.last_PC == recent_pc)
                pc_score -= 8; // strong penalty for recent PC match

        // Spatial locality: penalize blocks that are spatially close to recent addresses
        int spatial_score = 0;
        for (uint64_t recent_addr : ss.addr_history)
            if (is_spatially_close(bs.last_addr, recent_addr))
                spatial_score -= 4; // moderate penalty for spatial proximity

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
    MSARPSC_BlockState &bs = block_state[set][way];
    MSARPSC_SetState &ss = set_state[set];
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
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    // Optionally print distribution of last_access values
    uint64_t min_access = global_access_count, max_access = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            uint64_t la = block_state[set][way].last_access;
            if (la < min_access) min_access = la;
            if (la > max_access) max_access = la;
        }
    std::cout << "MSAR-PSC: Last access timestamp range: "
              << min_access << " - " << max_access << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    std::cout << "MSAR-PSC Heartbeat: Accesses=" << global_access_count << std::endl;
}