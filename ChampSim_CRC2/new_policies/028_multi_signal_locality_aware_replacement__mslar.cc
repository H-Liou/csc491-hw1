#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_LONG 0
#define RRIP_SHORT RRIP_MAX

// Frequency tracking
#define FREQ_TABLE_SIZE 8
#define FREQ_MAX 7

// Spatial reuse window
#define SPATIAL_WINDOW 4 // Track +/-2 neighbors

struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
    uint8_t freq; // Frequency counter
    uint8_t lru;  // Recency position
    uint8_t spatial; // Spatial reuse bitmap
};

struct SetState {
    std::vector<BlockMeta> meta;
    std::unordered_map<uint64_t, uint8_t> freq_table; // tag -> freq
    uint64_t last_insert_tag;
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0, 0, 0, 0});
        set.freq_table.clear();
        set.last_insert_tag = 0;
    }
}

// --- Helper: update LRU stack ---
void update_lru(SetState& s, uint32_t hit_way) {
    uint8_t old_lru = s.meta[hit_way].lru;
    for (uint32_t i = 0; i < LLC_WAYS; i++) {
        if (s.meta[i].lru < old_lru)
            s.meta[i].lru++;
    }
    s.meta[hit_way].lru = 0;
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

    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }

    // Victim selection: prefer blocks with freq==0 and spatial==0, break ties with LRU
    uint32_t victim = 0;
    bool found = false;
    uint8_t max_lru = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.meta[way].freq == 0 && s.meta[way].spatial == 0) {
            if (!found || s.meta[way].lru > max_lru) {
                victim = way;
                max_lru = s.meta[way].lru;
                found = true;
            }
        }
    }
    if (found)
        return victim;

    // Otherwise, evict block with highest RRIP, break ties with lowest freq then LRU
    uint8_t max_rrip = 0;
    uint8_t min_freq = FREQ_MAX+1;
    max_lru = 0;
    found = false;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.meta[way].rrip >= max_rrip) {
            if (!found || s.meta[way].freq < min_freq ||
                (s.meta[way].freq == min_freq && s.meta[way].lru > max_lru)) {
                victim = way;
                max_rrip = s.meta[way].rrip;
                min_freq = s.meta[way].freq;
                max_lru = s.meta[way].lru;
                found = true;
            }
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

    // --- Frequency table update ---
    auto it = s.freq_table.find(tag);
    if (hit) {
        if (it != s.freq_table.end()) {
            it->second = std::min<uint8_t>(FREQ_MAX, it->second + 1);
        } else {
            if (s.freq_table.size() >= FREQ_TABLE_SIZE)
                s.freq_table.erase(s.freq_table.begin());
            s.freq_table[tag] = 1;
        }
        s.meta[way].freq = s.freq_table[tag];
    } else {
        // On miss/insertion, set freq to 1
        if (s.freq_table.size() >= FREQ_TABLE_SIZE)
            s.freq_table.erase(s.freq_table.begin());
        s.freq_table[tag] = 1;
        s.meta[way].freq = 1;
    }

    // --- Spatial reuse bitmap update ---
    // If block inserted near previous insert, set spatial=1
    uint8_t spatial = 0;
    if (s.last_insert_tag != 0) {
        int64_t diff = (int64_t)tag - (int64_t)s.last_insert_tag;
        if (diff >= -SPATIAL_WINDOW/2 && diff <= SPATIAL_WINDOW/2 && diff != 0)
            spatial = 1;
    }
    s.meta[way].spatial = spatial;
    if (!hit)
        s.last_insert_tag = tag;

    // --- RRIP insertion policy ---
    // If freq >=2 or spatial==1, insert with RRIP_LONG (retain)
    // Otherwise, RRIP_SHORT (evict soon)
    uint8_t insert_rrip = RRIP_SHORT;
    if (s.meta[way].freq >= 2 || s.meta[way].spatial == 1)
        insert_rrip = RRIP_LONG;
    s.meta[way].rrip = insert_rrip;

    // On hit, reset RRIP
    if (hit)
        s.meta[way].rrip = RRIP_LONG;

    // --- LRU stack update ---
    update_lru(s, way);

    // --- Valid/tag update ---
    s.meta[way].valid = 1;
    s.meta[way].tag = tag;
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "MSLAR: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}