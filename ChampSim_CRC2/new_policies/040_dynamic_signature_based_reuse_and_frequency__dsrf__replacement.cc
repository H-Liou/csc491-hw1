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

// --- SHiP parameters ---
#define SHIP_MAX_RRPV 3
#define SHIP_INSERT_RRPV 2
#define SHIP_MAX_SIGNATURE 1024
#define SHIP_MAX_COUNTER 7

// --- Per-block metadata ---
struct DSRF_BlockMeta {
    uint8_t valid;
    uint64_t tag;
    uint8_t rrpv;
    uint16_t signature;
    uint8_t freq; // frequency counter (0-7)
};

// --- Per-set state ---
struct DSRF_SetState {
    std::vector<DSRF_BlockMeta> meta;
};

// --- Per-signature reuse predictor ---
std::array<uint8_t, SHIP_MAX_SIGNATURE> signature_reuse_table;

// --- Per-set states ---
std::vector<DSRF_SetState> sets(LLC_SETS);

// --- Helper: signature extraction ---
inline uint16_t get_signature(uint64_t PC) {
    // Simple hash: lower 10 bits of PC
    return (PC ^ (PC >> 10)) & (SHIP_MAX_SIGNATURE - 1);
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, 0, SHIP_MAX_RRPV, 0, 0});
    }
    signature_reuse_table.fill(3); // neutral initial reuse counter
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
    DSRF_SetState& s = sets[set];

    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // First, look for block with RRPV==SHIP_MAX_RRPV
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (s.meta[way].rrpv == SHIP_MAX_RRPV)
                return way;
        }
        // If none, increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            s.meta[way].rrpv = std::min<uint8_t>(SHIP_MAX_RRPV, s.meta[way].rrpv + 1);
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
    DSRF_SetState& s = sets[set];
    uint64_t tag = paddr >> 6;
    uint16_t sig = get_signature(PC);

    if (hit) {
        // On hit: promote block, increment frequency, update signature predictor
        s.meta[way].rrpv = 0;
        s.meta[way].freq = std::min<uint8_t>(SHIP_MAX_COUNTER, s.meta[way].freq + 1);
        signature_reuse_table[s.meta[way].signature] = std::min<uint8_t>(SHIP_MAX_COUNTER, signature_reuse_table[s.meta[way].signature] + 1);
    } else {
        // On fill: set block meta
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].signature = sig;
        s.meta[way].freq = 1;

        // Insert RRPV based on signature reuse counter
        uint8_t reuse = signature_reuse_table[sig];
        // If signature has high reuse (>=5), insert with RRPV=0 (long retention)
        // If moderate reuse (3-4), insert with RRPV=SHIP_INSERT_RRPV
        // If low reuse (<=2), insert with RRPV=SHIP_MAX_RRPV (evict soon)
        if (reuse >= 5)
            s.meta[way].rrpv = 0;
        else if (reuse >= 3)
            s.meta[way].rrpv = SHIP_INSERT_RRPV;
        else
            s.meta[way].rrpv = SHIP_MAX_RRPV;

        // On eviction, if block was not reused, decrement signature predictor
        // (simulate: if victim_addr != 0, find victim's signature and penalize)
        if (victim_addr != 0) {
            uint64_t victim_tag = victim_addr >> 6;
            for (uint32_t i = 0; i < LLC_WAYS; ++i) {
                if (s.meta[i].valid && s.meta[i].tag == victim_tag) {
                    uint16_t victim_sig = s.meta[i].signature;
                    // If block was not reused (freq==1), penalize
                    if (s.meta[i].freq <= 1)
                        signature_reuse_table[victim_sig] = std::max<uint8_t>(0, signature_reuse_table[victim_sig] - 1);
                    break;
                }
            }
        }
    }
}

// --- Stats ---
void PrintStats() {
    uint64_t total_hits = 0, total_misses = 0;
    for (const auto& set : sets) {
        for (const auto& block : set.meta) {
            if (block.valid)
                total_hits += block.freq - 1; // freq>1 means reused
            total_misses += 1; // every valid block was filled once
        }
    }
    double hitrate = (total_hits * 100.0) / (total_hits + total_misses + 1e-5);
    std::cout << "DSRF: Hits=" << total_hits << " Misses=" << total_misses
              << " HitRate=" << hitrate << "%" << std::endl;
}

void PrintStats_Heartbeat() {
    PrintStats();
}