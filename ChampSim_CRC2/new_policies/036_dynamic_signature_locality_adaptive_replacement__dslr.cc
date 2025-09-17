#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Parameters
#define DSLR_SIG_BITS 12 // signature bits for address phase detection
#define DSLR_SIG_WIN 8   // window size for recent signatures
#define DSLR_FREQ_MAX 15 // max reuse counter

struct DSLRBlockMeta {
    uint8_t valid;
    uint64_t tag;
    uint8_t lru;   // LRU position
    uint8_t freq;  // Reuse counter
    uint16_t sig;  // Signature (partial address hash)
};

struct DSLRSetState {
    std::array<uint16_t, DSLR_SIG_WIN> recent_sigs;
    uint32_t win_ptr;
    uint32_t hits;
    uint32_t misses;
    float locality_score; // moving average of locality
    std::vector<DSLRBlockMeta> meta;
};

std::vector<DSLRSetState> sets(LLC_SETS);

// --- Helper: compute signature locality ---
float compute_signature_locality(const DSLRSetState& s, uint16_t curr_sig) {
    uint32_t matches = 0;
    for (uint32_t i = 0; i < DSLR_SIG_WIN; ++i) {
        if (s.recent_sigs[i] == curr_sig)
            matches++;
    }
    return float(matches) / DSLR_SIG_WIN;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, 0, 0, 0});
        set.recent_sigs.fill(0);
        set.win_ptr = 0;
        set.hits = 0;
        set.misses = 0;
        set.locality_score = 0.0f;
    }
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
    DSLRSetState& s = sets[set];

    // Prefer invalid blocks first
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }

    // Compute current signature
    uint16_t curr_sig = (paddr >> 6) & ((1 << DSLR_SIG_BITS) - 1);

    // Update locality score (moving average)
    float sig_locality = compute_signature_locality(s, curr_sig);
    s.locality_score = (0.8f * s.locality_score) + (0.2f * sig_locality);

    // If locality is high, prefer evicting blocks with mismatched signature and lowest freq
    if (s.locality_score > 0.5f) {
        uint8_t min_freq = DSLR_FREQ_MAX + 1;
        uint8_t max_lru = 0;
        uint32_t victim = 0;
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            // Prefer blocks with mismatched signature
            if (s.meta[way].sig != curr_sig) {
                if (s.meta[way].freq < min_freq ||
                    (s.meta[way].freq == min_freq && s.meta[way].lru > max_lru)) {
                    min_freq = s.meta[way].freq;
                    max_lru = s.meta[way].lru;
                    victim = way;
                }
            }
        }
        // If all signatures match, fall back to lowest freq/highest LRU
        if (min_freq <= DSLR_FREQ_MAX)
            return victim;
    }

    // Otherwise (irregular phase), evict block with lowest freq, break ties with highest LRU
    uint8_t min_freq = DSLR_FREQ_MAX + 1;
    uint8_t max_lru = 0;
    uint32_t victim = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.meta[way].freq < min_freq ||
            (s.meta[way].freq == min_freq && s.meta[way].lru > max_lru)) {
            min_freq = s.meta[way].freq;
            max_lru = s.meta[way].lru;
            victim = way;
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
    DSLRSetState& s = sets[set];
    uint64_t tag = paddr >> 6;
    uint16_t sig = (paddr >> 6) & ((1 << DSLR_SIG_BITS) - 1);

    // Update recent signature history
    s.recent_sigs[s.win_ptr] = sig;
    s.win_ptr = (s.win_ptr + 1) % DSLR_SIG_WIN;

    // Update hit/miss stats
    if (hit) s.hits++; else s.misses++;

    // Update LRU for all valid blocks
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (s.meta[w].valid)
            s.meta[w].lru = std::min<uint8_t>(255, s.meta[w].lru + 1);
    }

    if (hit) {
        s.meta[way].lru = 0;
        s.meta[way].freq = std::min<uint8_t>(DSLR_FREQ_MAX, s.meta[way].freq + 1);
        // Update signature to current access
        s.meta[way].sig = sig;
    } else {
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].lru = 0;
        s.meta[way].freq = 1;
        s.meta[way].sig = sig;
    }
}

// --- Stats ---
void PrintStats() {
    uint64_t total_hits = 0, total_misses = 0;
    for (const auto& s : sets) {
        total_hits += s.hits;
        total_misses += s.misses;
    }
    std::cout << "DSLR: Hits=" << total_hits << " Misses=" << total_misses
              << " HitRate=" << (total_hits * 100.0 / (total_hits + total_misses)) << "%" << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}