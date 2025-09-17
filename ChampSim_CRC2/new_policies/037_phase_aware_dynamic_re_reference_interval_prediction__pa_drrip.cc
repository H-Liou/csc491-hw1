#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define RRPV_INSERT_SRRIP (RRPV_MAX - 1)
#define RRPV_INSERT_BRRIP (RRPV_MAX)
#define PA_SIG_BITS 12
#define PA_SIG_WIN 8
#define PA_PHASE_THRESHOLD 0.6f

struct PA_BlockMeta {
    uint8_t valid;
    uint64_t tag;
    uint8_t rrpv;
    uint16_t sig;
};

struct PA_SetState {
    std::array<uint16_t, PA_SIG_WIN> recent_sigs;
    uint32_t win_ptr;
    uint32_t hits;
    uint32_t misses;
    float locality_score; // moving average of signature locality
    bool use_srrip;       // phase mode
    std::vector<PA_BlockMeta> meta;
};

std::vector<PA_SetState> sets(LLC_SETS);

// --- Helper: compute signature locality ---
float compute_signature_locality(const PA_SetState& s, uint16_t curr_sig) {
    uint32_t matches = 0;
    for (uint32_t i = 0; i < PA_SIG_WIN; ++i) {
        if (s.recent_sigs[i] == curr_sig)
            matches++;
    }
    return float(matches) / PA_SIG_WIN;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, RRPV_MAX, 0});
        set.recent_sigs.fill(0);
        set.win_ptr = 0;
        set.hits = 0;
        set.misses = 0;
        set.locality_score = 0.0f;
        set.use_srrip = true;
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
    PA_SetState& s = sets[set];

    // Prefer invalid blocks first
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }

    // Standard DRRIP victim selection: find block with RRPV==MAX
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrpv == RRPV_MAX)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            s.meta[way].rrpv = std::min<uint8_t>(RRPV_MAX, s.meta[way].rrpv + 1);
        }
    }
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
    PA_SetState& s = sets[set];
    uint64_t tag = paddr >> 6;
    uint16_t sig = (paddr >> 6) & ((1 << PA_SIG_BITS) - 1);

    // Update recent signature history
    s.recent_sigs[s.win_ptr] = sig;
    s.win_ptr = (s.win_ptr + 1) % PA_SIG_WIN;

    // Update hit/miss stats
    if (hit) s.hits++; else s.misses++;

    // Update locality score (moving average)
    float sig_locality = compute_signature_locality(s, sig);
    s.locality_score = (0.8f * s.locality_score) + (0.2f * sig_locality);

    // Phase detection: if locality score is high, use SRRIP; else use BRRIP
    if (s.locality_score > PA_PHASE_THRESHOLD)
        s.use_srrip = true;
    else
        s.use_srrip = false;

    if (hit) {
        // On hit, set RRPV to 0 (most recently used)
        s.meta[way].rrpv = 0;
        s.meta[way].sig = sig;
    } else {
        // On fill, set RRPV according to phase
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].sig = sig;
        if (s.use_srrip)
            s.meta[way].rrpv = RRPV_INSERT_SRRIP;
        else
            // BRRIP: insert with RRPV_MAX with low probability, else RRPV_MAX-1
            s.meta[way].rrpv = (rand() % 32 == 0) ? RRPV_INSERT_SRRIP : RRPV_INSERT_BRRIP;
    }
}

// --- Stats ---
void PrintStats() {
    uint64_t total_hits = 0, total_misses = 0;
    for (const auto& s : sets) {
        total_hits += s.hits;
        total_misses += s.misses;
    }
    std::cout << "PA-DRRIP: Hits=" << total_hits << " Misses=" << total_misses
              << " HitRate=" << (total_hits * 100.0 / (total_hits + total_misses)) << "%" << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}