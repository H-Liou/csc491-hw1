#include <vector>
#include <cstdint>
#include <unordered_map>
#include <array>
#include <algorithm>
#include <iostream>
#include <cmath>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Parameters (tunable)
constexpr int PHASE_WINDOW = 128;       // Number of accesses per set before phase update
constexpr int PHASE_HISTORY = 4;        // Number of past phase signatures to keep
constexpr int PC_TABLE_SIZE = 4096;     // Entries in PC reuse predictor
constexpr int SPATIAL_WINDOW = 32;      // Tracks last N accesses for stride detection
constexpr int HIGH_REUSE_THRESHOLD = 4; // Minimum reuse count to consider "hot"
constexpr int LOW_REUSE_THRESHOLD = 1;  // Below this, considered "cold"

// Telemetry/statistics
uint64_t total_hits = 0;
uint64_t total_misses = 0;
std::array<uint64_t, LLC_SETS> set_phase_hits{};
std::array<uint64_t, LLC_SETS> set_phase_misses{};

// Replacement state per set
struct SetState {
    std::vector<uint64_t> recent_addrs;  // For stride/entropy analysis
    std::vector<uint64_t> recent_pcs;    // For phase signature
    int phase_id = 0;                    // Current phase signature
    std::array<int, LLC_WAYS> reuse_score{}; // Reuse score per line
    std::array<uint64_t, LLC_WAYS> last_pc{}; // PC of last access per line
};
std::array<SetState, LLC_SETS> sets;

// PC-based reuse predictor
struct PCEntry {
    int reuse_count = 0;
    int last_phase = 0;
};
std::unordered_map<uint64_t, PCEntry> pc_table;

// Helper: hash PC for table indexing
inline uint64_t pc_hash(uint64_t pc) {
    return pc ^ (pc >> 13);
}

// Helper: update phase signature for a set
int compute_phase_id(const std::vector<uint64_t>& pcs) {
    // Simple entropy-based phase detection
    std::unordered_map<uint64_t, int> freq;
    for (auto pc : pcs) freq[pc]++;
    double entropy = 0.0;
    int total = pcs.size();
    for (auto& kv : freq) {
        double p = double(kv.second) / total;
        entropy -= p * log2(p);
    }
    // Quantize entropy to phase id
    if (entropy < 2.0) return 0;         // Regular phase
    else if (entropy < 3.0) return 1;    // Mixed phase
    else return 2;                       // Irregular phase
}

// Helper: spatial stride detection
bool is_spatial_local(const std::vector<uint64_t>& addrs) {
    if (addrs.size() < 2) return false;
    std::vector<int64_t> strides;
    for (size_t i = 1; i < addrs.size(); ++i)
        strides.push_back(int64_t(addrs[i]) - int64_t(addrs[i-1]));
    // If most strides are similar, spatial locality is high
    std::unordered_map<int64_t, int> stride_freq;
    for (auto s : strides) stride_freq[s]++;
    int max_freq = 0;
    for (auto& kv : stride_freq) max_freq = std::max(max_freq, kv.second);
    return max_freq > int(strides.size() * 0.6); // >60% same stride
}

// Initialize replacement state
void InitReplacementState() {
    for (auto& s : sets) {
        s.recent_addrs.clear();
        s.recent_pcs.clear();
        s.phase_id = 0;
        s.reuse_score.fill(0);
        s.last_pc.fill(0);
    }
    pc_table.clear();
    total_hits = 0;
    total_misses = 0;
    set_phase_hits.fill(0);
    set_phase_misses.fill(0);
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
    auto& s = sets[set];

    // Update phase if window reached
    s.recent_pcs.push_back(PC);
    if (s.recent_pcs.size() > PHASE_WINDOW) {
        s.phase_id = compute_phase_id(s.recent_pcs);
        s.recent_pcs.clear();
    }

    // Update spatial window
    s.recent_addrs.push_back(paddr);
    if (s.recent_addrs.size() > SPATIAL_WINDOW)
        s.recent_addrs.erase(s.recent_addrs.begin());

    bool spatial_local = is_spatial_local(s.recent_addrs);

    // Victim selection logic:
    // 1. Prefer lines with lowest reuse score
    // 2. If phase is regular and spatial locality is high, protect lines accessed by stride
    // 3. If phase is irregular, prefer evicting lines with cold PC
    int victim = -1;
    int min_score = 1<<30;
    for (int way = 0; way < LLC_WAYS; ++way) {
        int score = s.reuse_score[way];
        uint64_t line_pc = s.last_pc[way];
        int pc_reuse = pc_table.count(pc_hash(line_pc)) ? pc_table[pc_hash(line_pc)].reuse_count : 0;

        // Penalize eviction of hot lines in regular phase
        if (s.phase_id == 0 && spatial_local && pc_reuse >= HIGH_REUSE_THRESHOLD)
            score += 10;

        // In irregular phase, more aggressive eviction of cold lines
        if (s.phase_id == 2 && pc_reuse <= LOW_REUSE_THRESHOLD)
            score -= 5;

        if (score < min_score) {
            min_score = score;
            victim = way;
        }
    }
    if (victim == -1) victim = 0; // fallback
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
    auto& s = sets[set];
    uint64_t pc_idx = pc_hash(PC);

    // Track hits/misses for stats
    if (hit) {
        total_hits++;
        set_phase_hits[set]++;
        s.reuse_score[way] = std::min(s.reuse_score[way] + 1, 15);
    } else {
        total_misses++;
        set_phase_misses[set]++;
        s.reuse_score[way] = 0;
    }

    // PC-based reuse predictor update
    auto& entry = pc_table[pc_idx];
    if (hit) entry.reuse_count = std::min(entry.reuse_count + 1, 15);
    else entry.reuse_count = std::max(entry.reuse_count - 1, 0);
    entry.last_phase = s.phase_id;

    // Update last PC for this line
    s.last_pc[way] = PC;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "APRLP Policy Stats:\n";
    std::cout << "Total hits: " << total_hits << "\n";
    std::cout << "Total misses: " << total_misses << "\n";
    double hit_rate = double(total_hits) / (total_hits + total_misses);
    std::cout << "Hit rate: " << hit_rate * 100.0 << "%\n";
    // Optional: per-phase stats
    int regular = 0, mixed = 0, irregular = 0;
    for (auto& s : sets) {
        if (s.phase_id == 0) regular++;
        else if (s.phase_id == 1) mixed++;
        else irregular++;
    }
    std::cout << "Phase distribution: Regular=" << regular << " Mixed=" << mixed << " Irregular=" << irregular << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[APRLP Heartbeat] Hits=" << total_hits << " Misses=" << total_misses << "\n";
}