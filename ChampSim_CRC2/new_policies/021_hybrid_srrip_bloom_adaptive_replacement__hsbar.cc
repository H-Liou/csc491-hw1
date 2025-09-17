#include <vector>
#include <cstdint>
#include <iostream>
#include <bitset>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_LONG 3   // Insert with 3 for streaming/irregular
#define RRIP_SHORT 0  // Insert with 0 for high locality

// Set Dueling constants
#define DUEL_SET_INTERVAL 64
#define DUEL_SET_COUNT (LLC_SETS / DUEL_SET_INTERVAL)
#define BLOOM_BITS 128
#define BLOOM_HASHES 3

// Per-block metadata
struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
};

// Per-set Bloom filter for reuse detection
struct BloomFilter {
    std::bitset<BLOOM_BITS> bits;
    void insert(uint64_t addr) {
        for (int i = 0; i < BLOOM_HASHES; i++) {
            uint64_t h = champsim_crc2(addr, i) % BLOOM_BITS;
            bits.set(h);
        }
    }
    bool possibly_contains(uint64_t addr) const {
        for (int i = 0; i < BLOOM_HASHES; i++) {
            uint64_t h = champsim_crc2(addr, i) % BLOOM_BITS;
            if (!bits.test(h)) return false;
        }
        return true;
    }
    void clear() { bits.reset(); }
};

// Per-set state
struct SetState {
    std::vector<BlockMeta> meta;
    BloomFilter bloom;
    uint64_t hits_srrip = 0, hits_bloom = 0;
    uint64_t accesses_srrip = 0, accesses_bloom = 0;
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0});
        set.bloom.clear();
        set.hits_srrip = set.hits_bloom = 0;
        set.accesses_srrip = set.accesses_bloom = 0;
    }
}

// --- Set Dueling: pick policy for set ---
enum PolicyType { POLICY_SRRIP, POLICY_BLOOM, POLICY_FOLLOW };

PolicyType GetSetPolicy(uint32_t set) {
    if (set % DUEL_SET_INTERVAL == 0) return POLICY_SRRIP;
    if (set % DUEL_SET_INTERVAL == 1) return POLICY_BLOOM;
    return POLICY_FOLLOW;
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
    SetState& s = sets[set];
    // Prefer invalid
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }
    // RRIP victim selection
    for (uint32_t round = 0; round < 2; round++) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip == RRIP_MAX)
                return way;
        }
        // Aging: increment all RRIP values
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip < RRIP_MAX)
                s.meta[way].rrip++;
        }
    }
    // Fallback: evict LRU (highest RRIP)
    uint32_t victim = 0;
    uint8_t max_rrip = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.meta[way].rrip >= max_rrip) {
            max_rrip = s.meta[way].rrip;
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
    SetState& s = sets[set];
    uint64_t tag = paddr >> 6;
    PolicyType policy = GetSetPolicy(set);

    // Determine which policy to use for "follow" sets
    static uint64_t global_hits_srrip = 0, global_hits_bloom = 0;
    static uint64_t global_accesses_srrip = 0, global_accesses_bloom = 0;
    PolicyType effective_policy = policy;

    if (policy == POLICY_FOLLOW) {
        // Use the winner between SRRIP and Bloom sets
        if (global_hits_bloom * 1.05 > global_hits_srrip) // Bloom wins (slight bias for adaptation)
            effective_policy = POLICY_BLOOM;
        else
            effective_policy = POLICY_SRRIP;
    }

    // Track stats for dueling sets
    if (policy == POLICY_SRRIP) {
        s.accesses_srrip++;
        if (hit) s.hits_srrip++;
        global_accesses_srrip++;
        if (hit) global_hits_srrip++;
    } else if (policy == POLICY_BLOOM) {
        s.accesses_bloom++;
        if (hit) s.hits_bloom++;
        global_accesses_bloom++;
        if (hit) global_hits_bloom++;
    }

    // On hit: promote block (set RRIP to 0) and insert address into Bloom filter
    if (hit) {
        s.meta[way].rrip = 0;
        s.bloom.insert(paddr >> 6);
    } else {
        // On miss/insertion: adapt insertion RRIP
        if (effective_policy == POLICY_BLOOM) {
            // If address seen recently, retain longer
            if (s.bloom.possibly_contains(paddr >> 6)) {
                s.meta[way].rrip = RRIP_SHORT;
            } else {
                s.meta[way].rrip = RRIP_LONG;
            }
        } else {
            // SRRIP: static insertion
            s.meta[way].rrip = RRIP_LONG;
        }
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        // Insert address into Bloom filter for future detection
        s.bloom.insert(paddr >> 6);
    }
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    // Aggregate stats
    total_hits = total_misses = total_evictions = 0;
    for (uint32_t set = 0; set < LLC_SETS; set++) {
        SetState& s = sets[set];
        total_hits += s.hits_srrip + s.hits_bloom;
        total_misses += (s.accesses_srrip + s.accesses_bloom) - (s.hits_srrip + s.hits_bloom);
    }
    std::cout << "HSBAR: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}