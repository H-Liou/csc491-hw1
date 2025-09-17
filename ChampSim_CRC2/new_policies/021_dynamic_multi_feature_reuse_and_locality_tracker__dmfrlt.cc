#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr uint8_t REUSE_MAX = 7;
constexpr uint8_t REUSE_MIN = 0;
constexpr uint8_t AGE_MAX = 15;
constexpr uint8_t AGE_MIN = 0;
constexpr uint8_t SPATIAL_STRIDE_WINDOW = 4; // tracks last 4 strides per set

struct LineState {
    uint64_t tag;
    uint8_t valid;
    uint8_t lru_position;
    uint8_t reuse_counter;
    uint8_t age;
    bool spatial_locality;
};

struct SetState {
    uint64_t last_addr;
    int stride_history[SPATIAL_STRIDE_WINDOW];
    int stride_ptr;
    int hit_count;
    int miss_count;
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t total_evictions = 0;
uint64_t reuse_evictions = 0;
uint64_t spatial_evictions = 0;
uint64_t lru_evictions = 0;
uint64_t spatial_promotions = 0;
uint64_t reuse_promotions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].valid = 0;
            line_states[set][way].lru_position = way;
            line_states[set][way].reuse_counter = 0;
            line_states[set][way].age = 0;
            line_states[set][way].spatial_locality = false;
        }
        set_states[set].last_addr = 0;
        std::memset(set_states[set].stride_history, 0, sizeof(set_states[set].stride_history));
        set_states[set].stride_ptr = 0;
        set_states[set].hit_count = 0;
        set_states[set].miss_count = 0;
    }
}

// Helper: check if stride is repeating in recent history
bool is_spatial_local(int stride, const SetState& sstate) {
    int count = 0;
    for (int i = 0; i < SPATIAL_STRIDE_WINDOW; ++i)
        if (sstate.stride_history[i] == stride && stride != 0)
            count++;
    return count >= 2; // at least 2 repeats in window
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    auto& lstates = line_states[set];

    // Prefer invalid block
    for (int way = 0; way < LLC_WAYS; ++way)
        if (!lstates[way].valid)
            return way;

    // Step 1: Find block with lowest reuse, not spatial, and highest age
    int victim = -1;
    uint8_t min_reuse = REUSE_MAX + 1;
    uint8_t max_age = AGE_MIN - 1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].reuse_counter <= REUSE_MIN + 1 &&
            !lstates[way].spatial_locality &&
            lstates[way].age >= AGE_MAX / 2) {
            // Prioritize old, non-local, non-reused blocks
            if (lstates[way].age > max_age || victim == -1) {
                victim = way;
                max_age = lstates[way].age;
            }
        }
    }
    if (victim != -1) {
        reuse_evictions++;
        total_evictions++;
        return victim;
    }

    // Step 2: Evict block with lowest reuse and not spatial
    min_reuse = REUSE_MAX + 1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (!lstates[way].spatial_locality && lstates[way].reuse_counter < min_reuse) {
            min_reuse = lstates[way].reuse_counter;
            victim = way;
        }
    }
    if (victim != -1) {
        spatial_evictions++;
        total_evictions++;
        return victim;
    }

    // Step 3: Fallback to LRU
    int lru_pos = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].lru_position > lru_pos) {
            lru_pos = lstates[way].lru_position;
            victim = way;
        }
    }
    lru_evictions++;
    total_evictions++;
    return victim;
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
    auto& lstates = line_states[set];
    auto& sstate = set_states[set];

    // --- Update reuse counter ---
    if (hit) {
        if (lstates[way].reuse_counter < REUSE_MAX) {
            lstates[way].reuse_counter++;
            reuse_promotions++;
        }
        lstates[way].age = AGE_MIN; // reset age on hit
    } else {
        if (lstates[way].reuse_counter > REUSE_MIN)
            lstates[way].reuse_counter--;
        if (lstates[way].age < AGE_MAX)
            lstates[way].age++;
    }

    // --- LRU stack update ---
    uint8_t old_pos = lstates[way].lru_position;
    for (int i = 0; i < LLC_WAYS; ++i) {
        if (lstates[i].lru_position < old_pos)
            lstates[i].lru_position++;
    }
    lstates[way].lru_position = 0;

    // --- Spatial locality detection ---
    int stride = 0;
    if (sstate.last_addr != 0)
        stride = static_cast<int>(paddr - sstate.last_addr);

    sstate.stride_history[sstate.stride_ptr] = stride;
    sstate.stride_ptr = (sstate.stride_ptr + 1) % SPATIAL_STRIDE_WINDOW;
    lstates[way].spatial_locality = is_spatial_local(stride, sstate);

    if (lstates[way].spatial_locality && hit) {
        // Boost reuse if spatial locality detected
        if (lstates[way].reuse_counter < REUSE_MAX)
            lstates[way].reuse_counter++;
        spatial_promotions++;
    }

    sstate.last_addr = paddr;

    // Stats
    if (hit)
        sstate.hit_count++;
    else
        sstate.miss_count++;

    lstates[way].tag = paddr;
    lstates[way].valid = 1;
}

void PrintStats() {
    std::cout << "DMFRLT: Total evictions: " << total_evictions << std::endl;
    std::cout << "DMFRLT: Reuse-based evictions: " << reuse_evictions << std::endl;
    std::cout << "DMFRLT: Spatial-based evictions: " << spatial_evictions << std::endl;
    std::cout << "DMFRLT: LRU evictions: " << lru_evictions << std::endl;
    std::cout << "DMFRLT: Reuse promotions: " << reuse_promotions << std::endl;
    std::cout << "DMFRLT: Spatial promotions: " << spatial_promotions << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "DMFRLT heartbeat: evictions=" << total_evictions
              << " reuse_evictions=" << reuse_evictions
              << " spatial_evictions=" << spatial_evictions
              << " lru_evictions=" << lru_evictions
              << " reuse_promotions=" << reuse_promotions
              << " spatial_promotions=" << spatial_promotions << std::endl;
}