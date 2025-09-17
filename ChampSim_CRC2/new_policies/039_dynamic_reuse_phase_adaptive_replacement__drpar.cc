#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <algorithm>
#include <random>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Policy parameters ---
#define DRPAR_WIN_SIZE 32           // Window size for locality/miss tracking
#define DRPAR_REUSE_THRESHOLD 0.4f  // Hit rate threshold for LRU mode
#define DRPAR_SPATIAL_THRESHOLD 0.2f// Hit rate threshold for SRRIP mode
#define DRPAR_BIP_PROB 32           // 1/BIP_PROB blocks inserted as MRU in BIP mode
#define DRPAR_STRIDE_RANDOM_THRESH 8// Random stride threshold for BIP mode

// --- Per-block metadata ---
struct DRPAR_BlockMeta {
    uint8_t valid;
    uint64_t tag;
    uint8_t lru;     // For LRU
    uint8_t rrpv;    // For SRRIP
};

// --- Per-set metadata ---
struct DRPAR_SetState {
    std::array<uint8_t, DRPAR_WIN_SIZE> recent_hits; // 1=hit, 0=miss
    uint32_t win_ptr;
    uint32_t hits;
    uint32_t misses;
    float hitrate;
    bool lru_mode;    // favor LRU if high hitrate
    bool srrip_mode;  // favor SRRIP if moderate hitrate
    bool bip_mode;    // pointer-chasing/irregular detected
    uint64_t last_addr;
    uint32_t stride_random;
    std::vector<DRPAR_BlockMeta> meta;
};

std::vector<DRPAR_SetState> sets(LLC_SETS);

// --- Helper: update hitrate ---
float compute_hitrate(const DRPAR_SetState& s) {
    uint32_t sum = 0;
    for (uint32_t i = 0; i < DRPAR_WIN_SIZE; ++i)
        sum += s.recent_hits[i];
    return float(sum) / DRPAR_WIN_SIZE;
}

// --- Helper: stride randomness detection ---
bool detect_bip_mode(DRPAR_SetState& s, uint64_t curr_addr) {
    if (s.last_addr == 0) {
        s.last_addr = curr_addr;
        return false;
    }
    int64_t stride = int64_t(curr_addr) - int64_t(s.last_addr);
    s.last_addr = curr_addr;
    // If stride is not small or not regular, increment randomness
    if (stride == 0 || std::abs(stride) > 4096)
        s.stride_random++;
    else
        s.stride_random = std::max(0u, s.stride_random - 1);
    return (s.stride_random >= DRPAR_STRIDE_RANDOM_THRESH);
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, 0, 3}); // valid=0, tag=0, lru=0, rrpv=3
        set.recent_hits.fill(0);
        set.win_ptr = 0;
        set.hits = 0;
        set.misses = 0;
        set.hitrate = 0.0f;
        set.lru_mode = false;
        set.srrip_mode = false;
        set.bip_mode = false;
        set.last_addr = 0;
        set.stride_random = 0;
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
    DRPAR_SetState& s = sets[set];

    // BIP mode: evict LRU block (to minimize pollution)
    if (s.bip_mode) {
        // Find invalid first
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        // Evict LRU block
        uint8_t max_lru = 0;
        uint32_t victim = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (s.meta[way].lru >= max_lru) {
                max_lru = s.meta[way].lru;
                victim = way;
            }
        }
        return victim;
    }

    // LRU mode: evict LRU block
    if (s.lru_mode) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        uint8_t max_lru = 0;
        uint32_t victim = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (s.meta[way].lru >= max_lru) {
                max_lru = s.meta[way].lru;
                victim = way;
            }
        }
        return victim;
    }

    // SRRIP mode or default: evict block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (!current_set[way].valid)
                return way;
            if (s.meta[way].rrpv == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            s.meta[way].rrpv = std::min<uint8_t>(3, s.meta[way].rrpv + 1);
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
    DRPAR_SetState& s = sets[set];
    uint64_t tag = paddr >> 6;

    // Update hit/miss window
    s.recent_hits[s.win_ptr] = hit ? 1 : 0;
    s.win_ptr = (s.win_ptr + 1) % DRPAR_WIN_SIZE;
    if (hit) s.hits++; else s.misses++;

    // Update hitrate and mode selection
    s.hitrate = compute_hitrate(s);
    s.lru_mode = (s.hitrate > DRPAR_REUSE_THRESHOLD);
    s.srrip_mode = (!s.lru_mode) && (s.hitrate > DRPAR_SPATIAL_THRESHOLD);

    // Stride randomness detection for BIP mode
    s.bip_mode = detect_bip_mode(s, paddr);

    if (hit) {
        // On hit, update LRU and RRPV
        uint8_t old_lru = s.meta[way].lru;
        for (uint32_t i = 0; i < LLC_WAYS; ++i)
            if (s.meta[i].lru < old_lru)
                s.meta[i].lru++;
        s.meta[way].lru = 0;
        s.meta[way].rrpv = 0;
    } else {
        // On fill, set block meta
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        // Insert policy
        if (s.bip_mode) {
            // BIP: Insert as LRU except 1/DRPAR_BIP_PROB as MRU
            static thread_local std::mt19937 gen(std::random_device{}());
            std::uniform_int_distribution<uint32_t> dist(0, DRPAR_BIP_PROB - 1);
            bool insert_mru = (dist(gen) == 0);
            for (uint32_t i = 0; i < LLC_WAYS; ++i)
                s.meta[i].lru++;
            s.meta[way].lru = insert_mru ? 0 : (LLC_WAYS - 1);
            s.meta[way].rrpv = insert_mru ? 0 : 3;
        } else if (s.lru_mode) {
            // LRU: insert as MRU
            for (uint32_t i = 0; i < LLC_WAYS; ++i)
                s.meta[i].lru++;
            s.meta[way].lru = 0;
            s.meta[way].rrpv = 0;
        } else if (s.srrip_mode) {
            // SRRIP: insert with RRPV=2
            s.meta[way].rrpv = 2;
            s.meta[way].lru = LLC_WAYS - 1;
        } else {
            // Default: insert with RRPV=3 (evict soon)
            s.meta[way].rrpv = 3;
            s.meta[way].lru = LLC_WAYS - 1;
        }
    }
}

// --- Stats ---
void PrintStats() {
    uint64_t total_hits = 0, total_misses = 0;
    for (const auto& s : sets) {
        total_hits += s.hits;
        total_misses += s.misses;
    }
    std::cout << "DRPAR: Hits=" << total_hits << " Misses=" << total_misses
              << " HitRate=" << (total_hits * 100.0 / (total_hits + total_misses)) << "%" << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}