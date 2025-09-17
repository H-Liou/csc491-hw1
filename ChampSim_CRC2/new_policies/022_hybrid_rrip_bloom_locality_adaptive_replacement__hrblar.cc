#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_LONG 3   // Insert with 3 for streaming/irregular
#define RRIP_SHORT 0  // Insert with 0 for high locality

// Bloom filter parameters
#define BLOOM_BITS 64 // bits per set
#define BLOOM_HASHES 3 // number of hash functions

struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
};

struct SetState {
    std::vector<BlockMeta> meta;
    uint64_t bloom; // 64-bit Bloom filter
};

std::vector<SetState> sets(LLC_SETS);

// --- Simple Bloom filter hash functions ---
inline uint32_t bloom_hash(uint64_t addr, int i) {
    // Three simple hash functions using CRC and bit shifts
    switch (i) {
        case 0: return champsim_crc2(addr, 0xA5A5) % BLOOM_BITS;
        case 1: return ((addr >> 6) ^ (addr << 13)) % BLOOM_BITS;
        case 2: return champsim_crc2(addr, 0x5A5A) % BLOOM_BITS;
        default: return 0;
    }
}

// --- Bloom filter operations ---
void bloom_insert(uint64_t &bloom, uint64_t addr) {
    for (int i = 0; i < BLOOM_HASHES; i++) {
        bloom |= (1ULL << bloom_hash(addr, i));
    }
}
bool bloom_query(uint64_t bloom, uint64_t addr) {
    for (int i = 0; i < BLOOM_HASHES; i++) {
        if (!(bloom & (1ULL << bloom_hash(addr, i))))
            return false;
    }
    return true;
}
void bloom_clear(uint64_t &bloom) {
    bloom = 0;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0});
        set.bloom = 0;
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
    SetState& s = sets[set];
    // Prefer invalid
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }
    // RRIP victim selection: pick block(s) with RRIP_MAX
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

    // On hit: promote block (set RRIP to 0) and insert block address into Bloom filter
    if (hit) {
        s.meta[way].rrip = 0;
        bloom_insert(s.bloom, paddr >> 6); // Use block address granularity
    } else {
        // On miss/insertion: adapt insertion RRIP based on Bloom filter (recent reuse)
        if (bloom_query(s.bloom, paddr >> 6)) {
            // Block recently reused: retain longer
            s.meta[way].rrip = RRIP_SHORT;
        } else {
            // Streaming/irregular: evict quickly
            s.meta[way].rrip = RRIP_LONG;
        }
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        // Insert block address into Bloom filter for future queries
        bloom_insert(s.bloom, paddr >> 6);
    }

    // Periodically clear Bloom filter to avoid staleness (every 4096 accesses per set)
    static std::array<uint32_t, LLC_SETS> bloom_counter = {};
    bloom_counter[set]++;
    if (bloom_counter[set] % 4096 == 0)
        bloom_clear(s.bloom);
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "HRBLAR: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}