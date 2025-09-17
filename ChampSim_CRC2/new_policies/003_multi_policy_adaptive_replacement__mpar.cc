#include <vector>
#include <array>
#include <unordered_map>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int SRW_WINDOW = 8;         // For spatial recency tracking
constexpr int LFU_DEPTH = 6;          // Last N hits per block for frequency
constexpr int PC_WIN = 8;             // Per-set PC histogram
constexpr int PHASE_WIN = 16;         // Window for adaptive phase switching

struct WayMeta {
    uint64_t tag;
    uint64_t last_access_cycle;
    int lfu_hits;               // Last N frequency counter
    uint64_t last_PC;
};

struct SetMeta {
    std::array<WayMeta, LLC_WAYS> ways;
    std::array<uint64_t, SRW_WINDOW> srw_addr_hist;  // For spatial recency
    int srw_ptr;

    std::unordered_map<uint64_t, int> pc_histogram;  // For PC correlation

    int hit_count;
    int miss_count;

    int phase_mode;    // 0=LFU, 1=SRW, 2=PC
    int phase_cnt[3];
    int acc_cnt; // count since last switch
    int lfu_total_hits;   // used in phase detection
    int srw_total_hits;
    int pc_total_hits;

    uint64_t last_cycle;
};

// global state for all LLC sets
std::array<SetMeta, LLC_SETS> set_table;
uint64_t global_cycle = 0;

void InitReplacementState() {
    for (auto& meta : set_table) {
        for (auto& w : meta.ways) {
            w.tag = 0;
            w.last_access_cycle = 0;
            w.lfu_hits = 0;
            w.last_PC = 0;
        }
        meta.srw_ptr = 0;
        meta.srw_addr_hist.fill(0);
        meta.pc_histogram.clear();

        meta.hit_count = meta.miss_count = 0;
        meta.phase_mode = 0;
        meta.phase_cnt[0] = meta.phase_cnt[1] = meta.phase_cnt[2] = 0;
        meta.acc_cnt = 0;
        meta.lfu_total_hits = 0;
        meta.srw_total_hits = 0;
        meta.pc_total_hits = 0;
        meta.last_cycle = 0;
    }
    global_cycle = 0;
}

// Adaptive phase selection
int phase_select(SetMeta& meta) {
    // Update phase every PHASE_WIN accesses
    meta.acc_cnt++;
    if (meta.acc_cnt >= PHASE_WIN) {
        // Pick phase with maximum recent hits
        int max_idx = 0;
        int max_val = meta.phase_cnt[0];
        for (int i = 1; i < 3; i++)
            if (meta.phase_cnt[i] > max_val) {
                max_idx = i;
                max_val = meta.phase_cnt[i];
            }
        meta.phase_mode = max_idx;
        meta.phase_cnt[0] = meta.phase_cnt[1] = meta.phase_cnt[2] = 0;
        meta.acc_cnt = 0;
    }
    return meta.phase_mode;
}

// Victim selection
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
    int cur_phase = phase_select(meta);

    int victim = 0;
    int min_score = 1e9;

    // Score each way according to phase
    for (int w = 0; w < LLC_WAYS; ++w) {
        WayMeta& wm = meta.ways[w];
        int score = 0;
        // LFU mode: prefer blocks with fewer hits (frequency)
        if (cur_phase == 0) { // LFU
            score = wm.lfu_hits * 2 + (global_cycle - wm.last_access_cycle) / 4;
        }
        // SRW (Spatial recency window): penalize addresses seen in last N accesses
        else if (cur_phase == 1) { // SRW
            bool seen = false;
            for (int i = 0; i < SRW_WINDOW; ++i) {
                if (current_set[w].address == meta.srw_addr_hist[i]) {
                    seen = true;
                    break;
                }
            }
            score = seen ? 1000 : 0;
            score += (global_cycle - wm.last_access_cycle) / 4; // tie-breaker
        }
        // PC-correlation pinning: victimize blocks whose PC is least frequent recently
        else if (cur_phase == 2) {
            int freq = 0;
            auto it = meta.pc_histogram.find(wm.last_PC);
            if (it != meta.pc_histogram.end())
                freq = it->second;
            score = 100 - freq; // lower freq = more likely victim
            score += (global_cycle - wm.last_access_cycle) / 6;
        }

        // Always tie-break with LRU (oldest gets higher score)
        score += (global_cycle > wm.last_access_cycle) ? (global_cycle - wm.last_access_cycle) / 10 : 0;

        if (score < min_score) {
            min_score = score;
            victim = w;
        }
    }
    return victim;
}

// Update replacement state on every fill/hit
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

    // update statistics
    if (hit) {
        meta.hit_count++;
        // LFU: upvote
        wmeta.lfu_hits = std::min(LFU_DEPTH, wmeta.lfu_hits+1);
        meta.phase_cnt[0]++;
        meta.lfu_total_hits++;

        // check if paddr was in SRW window
        bool match=false;
        for (int i = 0; i < SRW_WINDOW; ++i)
            if (meta.srw_addr_hist[i] == paddr)
                match=true;
        if (match) {
            meta.phase_cnt[1]++;
            meta.srw_total_hits++;
        }

        // PC phase
        meta.pc_histogram[PC]++;
        meta.phase_cnt[2]++;
        meta.pc_total_hits++;
    } else {
        meta.miss_count++;
        wmeta.lfu_hits = 0;
        meta.pc_histogram[PC]++;
    }

    // Update block meta info
    wmeta.tag = paddr;
    wmeta.last_access_cycle = global_cycle;
    wmeta.last_PC = PC;

    // Update SRW: circular window
    meta.srw_addr_hist[meta.srw_ptr] = paddr;
    meta.srw_ptr = (meta.srw_ptr + 1) % SRW_WINDOW;
}

// End-of-sim stats
void PrintStats() {
    int phase_count[3] = {0,0,0};
    int total_hits = 0, total_misses = 0;
    int lfu_total = 0, srw_total = 0, pc_total = 0;
    for (auto& meta : set_table) {
        phase_count[meta.phase_mode]++;
        total_hits += meta.hit_count;
        total_misses += meta.miss_count;
        lfu_total += meta.lfu_total_hits;
        srw_total += meta.srw_total_hits;
        pc_total += meta.pc_total_hits;
    }
    double hitrate = total_hits * 100.0 / (total_hits + total_misses + 1);

    std::cout << "MPAR Policy Final Stats:\n";
    std::cout << "Phase counts LFU:" << phase_count[0]
        << " SRW:" << phase_count[1] << " PC:" << phase_count[2] << "\n";
    std::cout << "LFU hits: " << lfu_total << " SRW hits: " << srw_total << " PC hits: " << pc_total << "\n";
    std::cout << "Total hits: " << total_hits << " Total misses: " << total_misses << "\n";
    std::cout << "Hit Rate: " << hitrate << "%\n";
}

void PrintStats_Heartbeat() {
    int phase_count[3] = {0,0,0};
    int total_hits = 0, total_misses = 0;
    for (auto& meta : set_table) {
        phase_count[meta.phase_mode]++;
        total_hits += meta.hit_count;
        total_misses += meta.miss_count;
    }
    double hitrate = total_hits * 100.0 / (total_hits + total_misses + 1);
    std::cout << "[Heartbeat] MPAR Phase: LFU=" << phase_count[0]
        << " SRW=" << phase_count[1] << " PC=" << phase_count[2] << "\n";
    std::cout << "[Heartbeat] MPAR Hit Rate: " << hitrate << "%\n";
}