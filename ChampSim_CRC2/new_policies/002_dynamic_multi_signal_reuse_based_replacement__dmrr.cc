#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Policy parameters
constexpr int RECENCY_DEPTH = 16;         // LRU stack depth
constexpr int PC_SIG_DEPTH = 8;           // History for PC-based reuse scoring
constexpr int STRIDE_WIN = 8;             // Stride locality window
constexpr int PHASE_WIN = 32;             // Window for phase adjustment

struct WayMeta {
    uint64_t last_access_cycle;
    uint64_t tag;
    uint64_t last_PC;
    int reuse_score;
    int lru_position;
};

struct SetMeta {
    uint64_t last_stride;
    int recent_stride_hits;
    std::array<uint64_t, PC_SIG_DEPTH> pc_history;
    int pc_ptr;
    std::array<uint64_t, STRIDE_WIN> addr_history;
    int addr_ptr;
    int last_victim;
    int phase_mode; // 0: PC/recency, 1: stride/spatial
    int phase_cnt[2];
    int cycles_since_last_switch;

    std::array<WayMeta, LLC_WAYS> ways;
    int hit_count;
    int miss_count;
};

// Global state for all LLC sets
std::array<SetMeta, LLC_SETS> set_table;

uint64_t global_cycle = 0;

// Utility: update PC and Addr history, stride
void update_access_pattern(SetMeta& meta, uint64_t addr, uint64_t PC) {
    meta.pc_history[meta.pc_ptr] = PC;
    meta.addr_history[meta.addr_ptr] = addr;
    meta.pc_ptr = (meta.pc_ptr + 1) % PC_SIG_DEPTH;
    meta.addr_ptr = (meta.addr_ptr + 1) % STRIDE_WIN;

    // Stride detection
    if (meta.addr_ptr > 0) {
        uint64_t stride = addr - meta.addr_history[(meta.addr_ptr - 1 + STRIDE_WIN) % STRIDE_WIN];
        if (stride != 0 && std::abs((int64_t)stride) < (1 << 15))
            meta.last_stride = stride;
    }
}

// Utility: returns 1 if current access fits spatial pattern, else 0
int spatial_match(const SetMeta& meta, uint64_t addr) {
    for (int i = 0; i < STRIDE_WIN; ++i) {
        if (meta.addr_history[i] == addr ||
            (std::abs((int64_t)meta.addr_history[i] - (int64_t)addr) <= std::abs((int64_t)meta.last_stride) &&
             meta.last_stride != 0))
            return 1;
    }
    return 0;
}

// Utility: returns 1 if PC is similar to recent stream
int pc_match(const SetMeta& meta, uint64_t PC) {
    for (int i = 0; i < PC_SIG_DEPTH; ++i)
        if (meta.pc_history[i] == PC)
            return 1;
    return 0;
}

// Adaptive phase detection
void update_phase(SetMeta& meta) {
    // Count stride hits (spatial) vs PC diversity (irregular)
    int stride_matches = 0, pc_variety = 0;
    std::unordered_map<uint64_t, int> pc_count;
    for (int i = 0; i < PC_SIG_DEPTH; ++i) {
        if (meta.pc_history[i])
            pc_count[meta.pc_history[i]]++;
    }
    pc_variety = pc_count.size();

    for (int i = 1; i < STRIDE_WIN; ++i) {
        int64_t s_now = (int64_t)(meta.addr_history[i] - meta.addr_history[i-1]);
        if (s_now == (int64_t)meta.last_stride && meta.last_stride != 0)
            stride_matches++;
    }

    if (stride_matches > STRIDE_WIN / 2)
        meta.phase_cnt[1]++;
    else
        meta.phase_cnt[0]++;

    // Switch phase every PHASE_WIN accesses based on majority
    meta.cycles_since_last_switch++;
    if (meta.cycles_since_last_switch >= PHASE_WIN) {
        meta.phase_mode = (meta.phase_cnt[1] > meta.phase_cnt[0]) ? 1 : 0;
        meta.phase_cnt[0] = meta.phase_cnt[1] = 0;
        meta.cycles_since_last_switch = 0;
    }
}

// Initialize replacement state
void InitReplacementState() {
    for (auto& meta : set_table) {
        meta.last_stride = 0;
        meta.recent_stride_hits = 0;
        std::fill(meta.pc_history.begin(), meta.pc_history.end(), 0);
        std::fill(meta.addr_history.begin(), meta.addr_history.end(), 0);
        meta.pc_ptr = meta.addr_ptr = 0;
        meta.last_victim = 0;
        meta.phase_mode = 0;
        meta.phase_cnt[0] = meta.phase_cnt[1] = 0;
        meta.cycles_since_last_switch = 0;
        meta.hit_count = meta.miss_count = 0;
        for (int w = 0; w < LLC_WAYS; ++w) {
            meta.ways[w].last_access_cycle = 0;
            meta.ways[w].tag = 0;
            meta.ways[w].last_PC = 0;
            meta.ways[w].reuse_score = 0;
            meta.ways[w].lru_position = w;
        }
    }
    global_cycle = 0;
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
    global_cycle++;
    SetMeta& meta = set_table[set];

    // Update phase detection
    update_phase(meta);

    // Score ways by predicted reuse
    int min_score = 1e9, victim = 0;
    for (int w = 0; w < LLC_WAYS; ++w) {
        WayMeta& wmeta = meta.ways[w];
        int recency = (int)(global_cycle - wmeta.last_access_cycle); // larger = less likely for reuse
        int pc_sim = (meta.phase_mode == 0) ? pc_match(meta, wmeta.last_PC) : 0;
        int spatial_sim = (meta.phase_mode == 1) ? spatial_match(meta, current_set[w].address) : 0;

        // Weighted score
        int score = 0;
        if (meta.phase_mode == 0) {
            // Phase: irregular/PC-aware
            score = recency - (pc_sim * 32); // penalize lines with recently matched PC
        } else {
            // Phase: regular/spatial
            score = recency - (spatial_sim * 32); // penalize lines recently matching stride
        }
        // Slight boosting for lines in LRU MRU
        if (wmeta.lru_position <= 1)
            score -= 8;

        wmeta.reuse_score = score;

        if (score < min_score) {
            min_score = score;
            victim = w;
        }
    }
    meta.last_victim = victim;
    return victim;
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
    SetMeta& meta = set_table[set];
    WayMeta& wmeta = meta.ways[way];

    if (hit)
        meta.hit_count++;
    else
        meta.miss_count++;

    update_access_pattern(meta, paddr, PC);

    // Update way meta
    wmeta.last_access_cycle = global_cycle;
    wmeta.tag = paddr;
    wmeta.last_PC = PC;

    // Move way to MRU in LRU stack
    int cur_pos = wmeta.lru_position;
    for (int k = 0; k < LLC_WAYS; ++k)
        if (meta.ways[k].lru_position < cur_pos)
            meta.ways[k].lru_position++;
    wmeta.lru_position = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    int phase_counts[2] = {0,0};
    int total_hits = 0, total_misses = 0;
    for (const auto& meta : set_table) {
        phase_counts[meta.phase_mode]++;
        total_hits += meta.hit_count;
        total_misses += meta.miss_count;
    }
    double hitrate = (double)total_hits / (total_hits + total_misses) * 100.0;
    std::cout << "DMRR Policy Final Stats:\n";
    std::cout << "Phase mode counts (0-PC/irregular, 1-Spatial): " << phase_counts[0] << " " << phase_counts[1] << "\n";
    std::cout << "Total hits: " << total_hits << " Total misses: " << total_misses << "\n";
    std::cout << "Hit Rate: " << hitrate << "%\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int phase_counts[2] = {0,0};
    int total_hits = 0, total_misses = 0;
    for (const auto& meta : set_table) {
        phase_counts[meta.phase_mode]++;
        total_hits += meta.hit_count;
        total_misses += meta.miss_count;
    }
    double hitrate = (double)total_hits / (total_hits + total_misses) * 100.0;
    std::cout << "[Heartbeat] DMRR Phases: PC/irregular=" << phase_counts[0]
              << " Spatial=" << phase_counts[1] << "\n";
    std::cout << "[Heartbeat] DMRR Hit Rate: " << hitrate << "%\n";
}