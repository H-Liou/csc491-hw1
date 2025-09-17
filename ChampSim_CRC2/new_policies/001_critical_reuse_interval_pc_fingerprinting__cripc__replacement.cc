#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include "../inc/champsim_crc2.h"

// Parameters (tune as needed)
#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16
constexpr int REUSE_WINDOW = 8; // accesses tracked per-line for CRI
constexpr int PC_SIG_BITS = 12; // hash size (bits)

struct LineState {
    std::array<uint64_t, REUSE_WINDOW> access_timestamps;
    int ts_ptr = 0;
    uint16_t pc_signature = 0; // recent PC (hashed)
    bool valid = false;
};
std::array<LineState, LLC_SETS*LLC_WAYS> line_states;

// Per-set recent PC window to detect dominant phase
struct SetState {
    std::array<uint16_t, REUSE_WINDOW> recent_pc_sigs;
    int pc_ptr = 0;
};
std::array<SetState, LLC_SETS> set_states;

uint64_t global_timestamp = 0; // for lifetime measurement

uint16_t hash_pc(uint64_t PC) {
    // Fast compression (can change)
    return ((PC >> 2) ^ PC ^ champsim_crc2(PC, 0xace1u)) & ((1 << PC_SIG_BITS) - 1);
}

// Init state
void InitReplacementState() {
    for (auto& l : line_states) {
        l.access_timestamps.fill(0);
        l.ts_ptr = 0;
        l.pc_signature = 0;
        l.valid = false;
    }
    for (auto& s : set_states) {
        s.recent_pc_sigs.fill(0);
        s.pc_ptr = 0;
    }
    global_timestamp = 1;
}

// Find victim: Evict line with largest CRI and least PC match
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    global_timestamp++;
    uint16_t cur_pc_sig = hash_pc(PC);

    // Measure PC phase similarity: line whose pc_signature matches recent window preferred
    SetState &st = set_states[set];

    // Scan all ways
    uint32_t victim = 0;
    uint64_t max_cri = 0;
    int min_pc_match = REUSE_WINDOW + 1;

    // Scan recent PC signatures in set
    int recent_matches[LLC_WAYS] = {};
    for (int way = 0; way < LLC_WAYS; ++way) {
        uint16_t sig = line_states[set*LLC_WAYS + way].pc_signature;
        recent_matches[way] = 0;
        for (int i = 0; i < REUSE_WINDOW; ++i)
            if (st.recent_pc_sigs[i] == sig && sig != 0)
                recent_matches[way]++;
    }

    // Compute CRI for each line: the difference between last two timestamps; if invalid, prefer eviction
    for (int way = 0; way < LLC_WAYS; ++way) {
        LineState &ls = line_states[set*LLC_WAYS + way];
        uint64_t cri = 0;
        if (!ls.valid) {
            victim = way;
            break;
        }
        else if (ls.ts_ptr == 0 || ls.access_timestamps[(ls.ts_ptr + REUSE_WINDOW - 1)%REUSE_WINDOW] == 0) {
            cri = global_timestamp; // never used: treat as dead
        }
        else {
            int last = (ls.ts_ptr + REUSE_WINDOW - 1) % REUSE_WINDOW;
            int prev = (ls.ts_ptr + REUSE_WINDOW - 2) % REUSE_WINDOW;
            cri = (ls.access_timestamps[last] > ls.access_timestamps[prev])
                  ? ls.access_timestamps[last] - ls.access_timestamps[prev] : 1;
        }
        // Prefer max CRI (i.e., dead), also lowest recent PC match
        if ((cri > max_cri) ||
            (cri == max_cri && recent_matches[way] < min_pc_match)) {
            victim = way;
            max_cri = cri;
            min_pc_match = recent_matches[way];
        }
    }
    return victim;
}

// Update replacement state after access
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
    global_timestamp++;
    uint16_t pc_sig = hash_pc(PC);
    LineState &ls = line_states[set*LLC_WAYS + way];

    // Insert new PC signature and time
    ls.pc_signature = pc_sig;
    ls.access_timestamps[ls.ts_ptr] = global_timestamp;
    ls.ts_ptr = (ls.ts_ptr + 1) % REUSE_WINDOW;
    ls.valid = true;

    // Update set's phase buffer
    SetState &st = set_states[set];
    st.recent_pc_sigs[st.pc_ptr] = pc_sig;
    st.pc_ptr = (st.pc_ptr + 1) % REUSE_WINDOW;
}

// Stats
uint64_t crit_hits = 0, crit_misses = 0;
std::array<uint64_t, LLC_SETS> set_hits = {0}, set_misses = {0};
std::array<uint64_t, LLC_WAYS> way_usage = {0};

void PrintStats() {
    uint64_t total_hits=0, total_misses=0;
    for (int s=0; s<LLC_SETS; ++s) {
        total_hits += set_hits[s];
        total_misses += set_misses[s];
    }
    std::cout << "CRIPC Final Stats:\n";
    std::cout << "Total Hits: " << total_hits << "  Misses: " << total_misses << "\n";
    double hit_rate = total_hits ? double(total_hits)/(total_hits+total_misses)*100. : 0.;
    std::cout << "Hit Rate: " << hit_rate << "%\n";
    std::cout << "Per Way Usage: ";
    for (int w=0; w<LLC_WAYS; ++w) std::cout << way_usage[w] << " ";
    std::cout << "\n";
}

void PrintStats_Heartbeat() {
    uint64_t total_hits=0, total_misses=0;
    for (int s=0; s<LLC_SETS; ++s) {
        total_hits += set_hits[s];
        total_misses += set_misses[s];
    }
    double hit_rate = total_hits ? double(total_hits)/(total_hits+total_misses)*100. : 0.;
    std::cout << "[HB] CRIPC Hit Rate: " << hit_rate << "%\n";
}