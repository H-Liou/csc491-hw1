#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_set>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

#define REGION_SIZE 512
#define SIGNATURE_HISTORY 16
#define PHASE_WINDOW 128
#define SRRIP_MAX 3

enum PhaseType { PHASE_UNKNOWN = 0, PHASE_SPATIAL = 1, PHASE_REUSE = 2, PHASE_RANDOM = 3 };

struct BlockMeta {
    uint64_t tag;
    uint8_t srrip;       // recency counter
    uint16_t signature;  // compact hash of address
    uint64_t region;
    bool valid;
};

struct SetMeta {
    std::vector<BlockMeta> blocks;
    std::vector<uint16_t> sig_history; // recent signatures
    uint32_t access_time;
    uint32_t region_hits;
    uint32_t sig_hits;
    PhaseType phase;
};

std::vector<SetMeta> sets(LLC_SETS);

// Simple hash for signatures
inline uint16_t addr_signature(uint64_t addr) {
    return (uint16_t)((addr >> 6) ^ (addr >> 13) ^ (addr >> 21));
}

inline uint64_t region_id(uint64_t paddr) {
    return paddr / REGION_SIZE;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].tag = 0;
            sets[s].blocks[w].srrip = SRRIP_MAX;
            sets[s].blocks[w].signature = 0;
            sets[s].blocks[w].region = 0;
            sets[s].blocks[w].valid = false;
        }
        sets[s].sig_history.clear();
        sets[s].access_time = 0;
        sets[s].region_hits = 0;
        sets[s].sig_hits = 0;
        sets[s].phase = PHASE_UNKNOWN;
    }
}

// Periodically classify set phase
void update_phase(SetMeta& sm, uint64_t curr_region, uint16_t curr_sig) {
    // Every PHASE_WINDOW accesses, update phase
    if (sm.access_time % PHASE_WINDOW == 0 && sm.access_time > 0) {
        float region_ratio = (float)sm.region_hits / (float)PHASE_WINDOW;
        float sig_ratio = (float)sm.sig_hits / (float)PHASE_WINDOW;
        if (region_ratio > 0.6)
            sm.phase = PHASE_SPATIAL;
        else if (sig_ratio > 0.25)
            sm.phase = PHASE_REUSE;
        else
            sm.phase = PHASE_RANDOM;
        sm.region_hits = 0;
        sm.sig_hits = 0;
    }

    // Track region and signature hits for next window
    // Region hit: any block in set matches curr_region
    for (const auto& b : sm.blocks)
        if (b.valid && b.region == curr_region) { sm.region_hits++; break; }
    // Signature hit: any block in set matches curr_sig
    for (const auto& b : sm.blocks)
        if (b.valid && b.signature == curr_sig) { sm.sig_hits++; break; }
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
    SetMeta &sm = sets[set];
    uint64_t curr_region = region_id(paddr);
    uint16_t curr_sig = addr_signature(paddr);

    update_phase(sm, curr_region, curr_sig);

    uint32_t victim = 0;

    if (sm.phase == PHASE_SPATIAL) {
        // Prefer to evict blocks outside current region, then highest srrip
        int best_score = -10000;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            int score = 0;
            if (!sm.blocks[w].valid) score += 100;
            if (sm.blocks[w].region != curr_region) score += 10;
            score -= sm.blocks[w].srrip;
            if (score > best_score) {
                best_score = score;
                victim = w;
            }
        }
    } else if (sm.phase == PHASE_REUSE) {
        // Prefer to evict blocks with oldest signature (not in history), then highest srrip
        std::unordered_set<uint16_t> sig_set(sm.sig_history.begin(), sm.sig_history.end());
        int best_score = -10000;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            int score = 0;
            if (!sm.blocks[w].valid) score += 100;
            if (sig_set.find(sm.blocks[w].signature) == sig_set.end()) score += 10;
            score -= sm.blocks[w].srrip;
            if (score > best_score) {
                best_score = score;
                victim = w;
            }
        }
    } else {
        // PHASE_RANDOM: SRRIP
        uint8_t max_srrip = 0;
        std::vector<uint32_t> candidates;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (!sm.blocks[w].valid) {
                victim = w;
                break;
            }
            if (sm.blocks[w].srrip > max_srrip) {
                max_srrip = sm.blocks[w].srrip;
                candidates.clear();
                candidates.push_back(w);
            } else if (sm.blocks[w].srrip == max_srrip) {
                candidates.push_back(w);
            }
        }
        if (candidates.size() > 1) {
            victim = candidates[rand() % candidates.size()];
        }
    }
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
    SetMeta &sm = sets[set];
    BlockMeta &bm = sm.blocks[way];
    sm.access_time++;

    uint64_t curr_region = region_id(paddr);
    uint16_t curr_sig = addr_signature(paddr);

    // Update signature history (FIFO)
    if (sm.sig_history.size() >= SIGNATURE_HISTORY)
        sm.sig_history.erase(sm.sig_history.begin());
    sm.sig_history.push_back(curr_sig);

    if (hit) {
        bm.srrip = 0; // MRU on hit
    } else {
        // Insert policy depends on phase
        if (sm.phase == PHASE_SPATIAL) {
            bm.srrip = 1;
        } else if (sm.phase == PHASE_REUSE) {
            bm.srrip = 2;
        } else {
            bm.srrip = SRRIP_MAX;
        }
    }
    bm.tag = paddr;
    bm.signature = curr_sig;
    bm.region = curr_region;
    bm.valid = true;
}

// Print end-of-simulation statistics
void PrintStats() {
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " phase: " << sets[s].phase << " | ";
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            std::cout << "[S:" << (int)sets[s].blocks[w].srrip
                << ",G:" << (int)sets[s].blocks[w].region
                << ",V:" << sets[s].blocks[w].valid << "] ";
        }
        std::cout << "\n";
    }
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}