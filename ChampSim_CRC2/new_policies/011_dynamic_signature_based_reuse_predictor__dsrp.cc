#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int SIG_HISTORY = 8;      // Per-set signature history size
constexpr int MAX_REUSE_SCORE = 7;  // Per-line reuse score (3 bits)
constexpr int DECAY_ON_MISS = 2;    // Amount to decay reuse score on miss
constexpr int PROTECT_SCORE = 4;    // Minimum score to protect from eviction

// Utility: Simple signature from PC and paddr (can be improved)
inline uint32_t make_signature(uint64_t PC, uint64_t paddr) {
    return (uint32_t)((PC ^ (paddr >> 6)) & 0xFFFF);
}

// Per-line state
struct LineState {
    uint64_t tag;
    uint32_t signature;
    uint8_t reuse_score;
    uint8_t valid;
    int lru_position;
};

// Per-set state
struct SetState {
    std::vector<uint32_t> recent_signatures; // Last SIG_HISTORY signatures
    std::unordered_map<uint32_t, uint8_t> sig_freq; // Frequency of recent signatures
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Stats
uint64_t total_evictions = 0;
uint64_t protected_evictions = 0;
uint64_t unprotected_evictions = 0;

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].signature = 0;
            line_states[set][way].reuse_score = 0;
            line_states[set][way].valid = 0;
            line_states[set][way].lru_position = way;
        }
        set_states[set].recent_signatures.assign(SIG_HISTORY, 0);
        set_states[set].sig_freq.clear();
    }
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
    auto& lstates = line_states[set];
    auto& sstate = set_states[set];

    uint32_t victim = 0;
    int min_score = lstates[0].reuse_score;
    int max_lru = lstates[0].lru_position;
    bool found_invalid = false;

    // Prefer invalid block
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (!lstates[way].valid) {
            victim = way;
            found_invalid = true;
            break;
        }
    }
    if (found_invalid) {
        return victim;
    }

    // Otherwise, select block with lowest reuse score and not recently observed signature
    for (int way = 0; way < LLC_WAYS; ++way) {
        uint8_t score = lstates[way].reuse_score;
        uint32_t sig = lstates[way].signature;
        bool recently_used = (sstate.sig_freq.count(sig) > 0);
        // Prefer to evict blocks with low score and signature not recently used
        if ((score < PROTECT_SCORE && !recently_used) ||
            (score < min_score) ||
            (score == min_score && lstates[way].lru_position > max_lru)) {
            min_score = score;
            max_lru = lstates[way].lru_position;
            victim = way;
        }
    }
    if (line_states[set][victim].reuse_score >= PROTECT_SCORE)
        protected_evictions++;
    else
        unprotected_evictions++;
    total_evictions++;
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
    auto& lstates = line_states[set];
    auto& sstate = set_states[set];

    uint32_t sig = make_signature(PC, paddr);

    // Update per-line state
    lstates[way].tag = paddr;
    lstates[way].signature = sig;
    lstates[way].valid = 1;

    // Update reuse score
    if (hit) {
        lstates[way].reuse_score = std::min((int)lstates[way].reuse_score + 1, MAX_REUSE_SCORE);
    } else {
        lstates[way].reuse_score = (lstates[way].reuse_score > DECAY_ON_MISS) ?
                                    lstates[way].reuse_score - DECAY_ON_MISS : 0;
    }

    // Update LRU positions
    int prev_lru = lstates[way].lru_position;
    for (int i = 0; i < LLC_WAYS; ++i) {
        if (lstates[i].lru_position < prev_lru)
            lstates[i].lru_position++;
    }
    lstates[way].lru_position = 0;

    // Update per-set recent signature history and frequency table
    if (sstate.recent_signatures.size() >= SIG_HISTORY)
        sstate.recent_signatures.erase(sstate.recent_signatures.begin());
    sstate.recent_signatures.push_back(sig);

    sstate.sig_freq.clear();
    for (auto s : sstate.recent_signatures)
        sstate.sig_freq[s]++;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DSRP: Total evictions: " << total_evictions << std::endl;
    std::cout << "DSRP: Protected evictions: " << protected_evictions << std::endl;
    std::cout << "DSRP: Unprotected evictions: " << unprotected_evictions << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DSRP heartbeat: evictions=" << total_evictions
              << " protected=" << protected_evictions
              << " unprotected=" << unprotected_evictions << std::endl;
}