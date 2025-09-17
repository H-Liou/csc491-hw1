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
#define RRIP_INSERT_LONG 2   // Insert with 2 for low-locality/pointer-chasing
#define RRIP_INSERT_SHORT 0  // Insert with 0 for high-locality/reuse

// Bloom filter parameters
#define BLOOM_BITS 32
#define BLOOM_HASHES 2

struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
};

// Per-set state
struct SetState {
    std::vector<BlockMeta> meta;
    std::bitset<BLOOM_BITS> bloom; // Recent tags seen (temporal locality)
    uint32_t bloom_reset_ctr;
    uint64_t last_addr;
    int64_t last_stride;
    uint32_t stride_hits;
    uint32_t stride_total;
    bool stride_phase; // true = regular stride detected
    uint32_t pointer_chase_hits;
    uint32_t pointer_chase_total;
    bool pointer_phase; // true = pointer-chasing detected
    uint64_t last_PC;
};

std::vector<SetState> sets(LLC_SETS);

// --- Simple Bloom filter functions ---
inline void bloom_insert(std::bitset<BLOOM_BITS>& bloom, uint64_t tag) {
    uint32_t h1 = champsim_crc32(tag) % BLOOM_BITS;
    uint32_t h2 = champsim_crc32(tag ^ 0x5bd1e995) % BLOOM_BITS;
    bloom.set(h1);
    bloom.set(h2);
}
inline bool bloom_query(const std::bitset<BLOOM_BITS>& bloom, uint64_t tag) {
    uint32_t h1 = champsim_crc32(tag) % BLOOM_BITS;
    uint32_t h2 = champsim_crc32(tag ^ 0x5bd1e995) % BLOOM_BITS;
    return bloom.test(h1) && bloom.test(h2);
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0});
        set.bloom.reset();
        set.bloom_reset_ctr = 0;
        set.last_addr = 0;
        set.last_stride = 0;
        set.stride_hits = 0;
        set.stride_total = 0;
        set.stride_phase = false;
        set.pointer_chase_hits = 0;
        set.pointer_chase_total = 0;
        set.pointer_phase = false;
        set.last_PC = 0;
    }
}

// --- Per-set stride and pointer-chasing detector ---
void UpdatePhase(SetState& s, uint64_t paddr, uint64_t PC) {
    // Stride detection (spatial locality)
    s.stride_total++;
    int64_t stride = paddr - s.last_addr;
    if (s.last_addr && stride == s.last_stride && stride != 0)
        s.stride_hits++;
    s.last_stride = stride;
    s.last_addr = paddr;
    if (s.stride_total >= 128) {
        s.stride_phase = (s.stride_hits * 100 / s.stride_total) > 60;
        s.stride_hits = 0;
        s.stride_total = 0;
    }
    // Pointer-chasing detection (irregular, control-dominated)
    s.pointer_chase_total++;
    // Heuristic: if PC changes frequently and stride is irregular, pointer-chasing likely
    if ((PC != s.last_PC) && (abs(stride) > 64 || stride == 0)) // stride==0: dereferencing same pointer
        s.pointer_chase_hits++;
    s.last_PC = PC;
    if (s.pointer_chase_total >= 128) {
        s.pointer_phase = (s.pointer_chase_hits * 100 / s.pointer_chase_total) > 40;
        s.pointer_chase_hits = 0;
        s.pointer_chase_total = 0;
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
        // If none found, increment all RRIP values (aging)
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip < RRIP_MAX)
                s.meta[way].rrip++;
        }
    }
    // Fallback: evict highest RRIP
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

    UpdatePhase(s, paddr, PC);

    // Periodically reset Bloom filter to avoid staleness
    s.bloom_reset_ctr++;
    if (s.bloom_reset_ctr >= 4096) {
        s.bloom.reset();
        s.bloom_reset_ctr = 0;
    }

    // On hit: promote block (set RRIP to 0), insert tag into Bloom filter
    if (hit) {
        s.meta[way].rrip = 0;
        bloom_insert(s.bloom, tag);
    } else {
        // On miss/insertion: adapt insertion RRIP based on phase and Bloom filter
        bool reuse_predicted = bloom_query(s.bloom, tag);
        if ((s.stride_phase && !s.pointer_phase) || reuse_predicted) {
            // High spatial locality or recently reused: retain longer
            s.meta[way].rrip = RRIP_INSERT_SHORT;
        } else if (s.pointer_phase) {
            // Pointer-chasing: insert with long RRIP for quick eviction
            s.meta[way].rrip = RRIP_INSERT_LONG;
        } else {
            // Default: moderate retention
            s.meta[way].rrip = 1;
        }
        // Insert tag into Bloom filter for future reuse prediction
        bloom_insert(s.bloom, tag);
    }
    s.meta[way].valid = 1;
    s.meta[way].tag = tag;
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "HRRIP-BPSD: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}