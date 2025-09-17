#include <vector>
#include <array>
#include <cstdint>
#include <cassert>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int PROTECTED_SIZE = 6;      // BS-LRU protected segment size
constexpr int EPOCH_LEN = 4096;        // Set-dueling epoch (in accesses)
constexpr int NUM_LEADER_SETS = 32;    // Number of leader sets per policy

struct BlockMeta {
    uint64_t tag = 0;
    bool valid = false;
    int lru = 0;         // For LRU stack position
    bool protected_bslru = false;
};

struct SetState {
    std::array<BlockMeta, LLC_WAYS> blocks;
    int recent_hits_lru = 0;
    int recent_hits_bslru = 0;
    int recent_accesses = 0;
    bool is_leader_lru = false;
    bool is_leader_bslru = false;
    int active_policy = 0;    // 0=LRU, 1=BS-LRU

    // For stats
    int hits = 0;
    int misses = 0;
};

std::array<SetState, LLC_SETS> sets;
int global_active_policy = 0;   // 0: LRU, 1: BS-LRU
int epoch_count = 0;

// Pick leader sets (fixed, hashed mapping)
inline bool is_leader_lru(uint32_t set_idx) {
    constexpr uint32_t MAGIC1 = 0x9e3779b9;
    return ((set_idx * MAGIC1) % LLC_SETS) < NUM_LEADER_SETS;
}
inline bool is_leader_bslru(uint32_t set_idx) {
    constexpr uint32_t MAGIC2 = 0x7f4a7c15;
    return ((set_idx * MAGIC2) % LLC_SETS) < NUM_LEADER_SETS;
}

void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (int w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].tag = 0;
            sets[s].blocks[w].valid = false;
            sets[s].blocks[w].lru = w; // LRU stack order - 0=MRU, 15=LRU
            sets[s].blocks[w].protected_bslru = false;
        }
        sets[s].recent_hits_lru = 0;
        sets[s].recent_hits_bslru = 0;
        sets[s].recent_accesses = 0;
        sets[s].is_leader_lru = is_leader_lru(s);
        sets[s].is_leader_bslru = is_leader_bslru(s);
        sets[s].active_policy = 0;
        sets[s].hits = 0;
        sets[s].misses = 0;
    }
    global_active_policy = 0;
    epoch_count = 0;
}

// Efficient lookup: return way index or -1
inline int find_block(uint32_t set, uint64_t tag) {
    for (int w = 0; w < LLC_WAYS; ++w)
        if (sets[set].blocks[w].valid && sets[set].blocks[w].tag == tag)
            return w;
    return -1;
}

// Set-dueling update: called by all sets
void update_set_dueling(uint32_t set, int hit_lru, int hit_bslru) {
    if (sets[set].is_leader_lru)
        sets[set].recent_hits_lru += hit_lru;
    if (sets[set].is_leader_bslru)
        sets[set].recent_hits_bslru += hit_bslru;
    sets[set].recent_accesses++;

    // Periodically re-evaluate
    if (sets[set].recent_accesses >= EPOCH_LEN) {
        int sum_lru = 0, sum_bslru = 0;
        for (auto& st : sets) {
            sum_lru += st.recent_hits_lru;
            sum_bslru += st.recent_hits_bslru;
        }
        // If BS-LRU wins, switch policy; else stick to LRU
        global_active_policy = (sum_bslru > sum_lru) ? 1 : 0;
        // Reset per-set counters
        for (auto& st : sets)
            st.recent_hits_lru = st.recent_hits_bslru = st.recent_accesses = 0;
        epoch_count++;
    }
    // All sets follow global, except leaders (each leader always uses their own assigned policy)
    if (sets[set].is_leader_lru)
        sets[set].active_policy = 0;
    else if (sets[set].is_leader_bslru)
        sets[set].active_policy = 1;
    else
        sets[set].active_policy = global_active_policy;
}

// Get victim for classic LRU
int get_victim_LRU(uint32_t set) {
    // Pick block with max lru
    int victim = 0, max_lru = sets[set].blocks[0].lru;
    for (int w = 1; w < LLC_WAYS; ++w) {
        if (sets[set].blocks[w].lru > max_lru) {
            victim = w;
            max_lru = sets[set].blocks[w].lru;
        }
    }
    return victim;
}

// Get victim for BS-LRU
int get_victim_BSLRU(uint32_t set) {
    // Prefer to evict a non-protected block (probationary)
    int best = -1;
    for (int w = 0; w < LLC_WAYS; ++w)
        if (sets[set].blocks[w].valid && !sets[set].blocks[w].protected_bslru) {
            best = w;
            break;
        }
    if (best != -1) return best;
    // All blocks protected: evict LRU among protected
    int victim = 0, max_lru = sets[set].blocks[0].lru;
    for (int w = 1; w < LLC_WAYS; ++w) {
        if (sets[set].blocks[w].lru > max_lru) {
            victim = w;
            max_lru = sets[set].blocks[w].lru;
        }
    }
    return victim;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    const auto& st = sets[set];
    if (st.active_policy == 0)
        return get_victim_LRU(set);
    else
        return get_victim_BSLRU(set);
}

// Update LRU stack after hit/fill
void update_LRU_stack(uint32_t set, int way) {
    int old_lru = sets[set].blocks[way].lru;
    for (int w = 0; w < LLC_WAYS; ++w)
        if (sets[set].blocks[w].lru < old_lru)
            sets[set].blocks[w].lru++;
    sets[set].blocks[way].lru = 0;
}

// BS-LRU: promote to protected segment if re-used; else probationary (not protected)
void update_BSLRU_stack(uint32_t set, int way, uint8_t hit) {
    int cur_prot = 0;
    for (int w = 0; w < LLC_WAYS; ++w) {
        if (sets[set].blocks[w].protected_bslru)
            cur_prot++;
    }
    // If re-use (hit), promote to protected if not already
    if (hit && !sets[set].blocks[way].protected_bslru && cur_prot < PROTECTED_SIZE)
        sets[set].blocks[way].protected_bslru = true;
    // Hits on already protected: nothing changes, just move to MRU of protected
    if (hit && sets[set].blocks[way].protected_bslru) {}
    // New fill (miss): always demote victim to probationary
    if (!hit)
        sets[set].blocks[way].protected_bslru = false;

    // Update LRU: protected blocks given lower lru order (MRU stack among protected, followed by probationary)
    // First, assign ranks
    int next_lru = 0;
    // MRU ordering for protected
    for (int k = 0; k < 2; ++k) { // k=0: protected, k=1: probation
        for (int w = 0; w < LLC_WAYS; ++w) {
            if ((k == 0 && sets[set].blocks[w].protected_bslru) ||
                (k == 1 && !sets[set].blocks[w].protected_bslru)) {
                sets[set].blocks[w].lru = next_lru;
                next_lru++;
            }
        }
    }
    // Move just hit/fill block to MRU of its segment
    int way_lru_init = sets[set].blocks[way].lru;
    for (int w = 0; w < LLC_WAYS; ++w)
        if ((sets[set].blocks[w].protected_bslru == sets[set].blocks[way].protected_bslru) &&
            sets[set].blocks[w].lru < way_lru_init)
            sets[set].blocks[w].lru++;
    sets[set].blocks[way].lru = (sets[set].blocks[way].protected_bslru) ? 0 : cur_prot;
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
    // On every access: update hit/miss counters for stats and set-dueling
    int is_lru = (sets[set].active_policy == 0);
    int is_bslru = (sets[set].active_policy == 1);
    update_set_dueling(set, hit * is_lru, hit * is_bslru);

    sets[set].blocks[way].tag = paddr;
    sets[set].blocks[way].valid = true;

    if (sets[set].active_policy == 0)
        update_LRU_stack(set, way);
    else
        update_BSLRU_stack(set, way, hit);

    if (hit) sets[set].hits++;
    else     sets[set].misses++;
}

void PrintStats() {
    int total_hits = 0, total_misses = 0;
    int pol_count[2] = {0,0};
    for (auto& st : sets) {
        total_hits += st.hits;
        total_misses += st.misses;
        pol_count[st.active_policy]++;
    }
    double hitrate = 100.0 * total_hits / (total_hits + total_misses + 1);
    std::cout << "DAS-LRU Policy: Active Policy LRU=" << pol_count[0]
        << " BS-LRU=" << pol_count[1]
        << " | Total hits=" << total_hits << " Total misses=" << total_misses
        << " | Hit rate=" << hitrate << "%\n";
    std::cout << "Epochs: " << epoch_count << " | Final policy=" << (global_active_policy == 0 ? "LRU" : "BS-LRU") << "\n";
}

void PrintStats_Heartbeat() {
    int pol_count[2] = {0,0}, hsum = 0, msum = 0;
    for (auto& st : sets) {
        pol_count[st.active_policy]++;
        hsum += st.hits;
        msum += st.misses;
    }
    double hitrate = 100.0 * hsum / (hsum + msum + 1);
    std::cout << "[Heartbeat] DAS-LRU Active Policy: LRU=" << pol_count[0]
        << " BS-LRU=" << pol_count[1]
        << " | Hit rate=" << hitrate << "%\n";
}